#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavfilter/avfilter.h>
#include <libavformat/avformat.h>
#include <libavutil/avutil.h>
#include <libavutil/opt.h>
#include <libswresample/swresample.h>
#include <libswscale/swscale.h>
}

#include <SDL2/SDL.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

struct NetworkMetrics {
    double  packet_loss_rate     = 0.0;
    double  average_latency      = 0.0;
    double  bandwidth            = 0.0;
    int64_t last_packet_time     = 0;
    int64_t total_packets        = 0;
    int64_t lost_packets         = 0;
    double  jitter               = 0.0;
    int64_t bytes_received       = 0;
    int64_t bytes_last_second    = 0;
    int64_t last_bandwidth_check = 0;
    int     mtu_size             = 1500;
    double  video_bitrate        = 0.0;

    mutable std::mutex metrics_mutex;
};

struct AdaptiveSettings {
    int     buffer_size        = -1;
    int     reorder_queue_size = -1;
    int64_t timeout            = 30000000;
    bool    prefer_tcp         = true;
    int     initial_pause      = 0;
    int     packet_size        = 188;
};

struct PacketQueue {
    std::queue<AVPacket*>   packets;
    std::mutex              mutex;
    std::condition_variable cond_var;
    int                     max_packets = 100;
    int                     min_packets = 10;
    bool                    finished    = false;
    int64_t                 total_size  = 0;
    int64_t                 max_size    = 15 * 1024 * 1024;  // 15 MB default

    void push(AVPacket* pkt) {
        std::lock_guard<std::mutex> lock(mutex);

        if (packets.size( ) >= ( size_t ) max_packets ||
            total_size >= max_size) {
            spdlog::warn(
                "Packet queue full (size={}, bytes={}), dropping oldest packet",
                packets.size( ), total_size);
            if (!packets.empty( )) {
                AVPacket* old_pkt = packets.front( );
                packets.pop( );
                total_size -= old_pkt->size;
                av_packet_free(&old_pkt);
            }
        }

        AVPacket* new_pkt = av_packet_alloc( );
        av_packet_ref(new_pkt, pkt);
        packets.push(new_pkt);
        total_size += pkt->size;
        cond_var.notify_one( );
    }

    AVPacket* pop(int timeout_ms = 100) {
        std::unique_lock<std::mutex> lock(mutex);

        auto now      = std::chrono::steady_clock::now( );
        auto deadline = now + std::chrono::milliseconds(timeout_ms);

        while (packets.empty( ) && !finished) {
            if (cond_var.wait_until(lock, deadline) ==
                std::cv_status::timeout) {
                return nullptr;
            }
        }

        if (packets.empty( )) {
            return nullptr;
        }

        AVPacket* pkt = packets.front( );
        packets.pop( );
        total_size -= pkt->size;
        return pkt;
    }

    int size( ) {
        std::lock_guard<std::mutex> lock(mutex);
        return packets.size( );
    }

    void adapt_to_network(const NetworkMetrics& metrics) {
        std::lock_guard<std::mutex> lock(mutex);

        if (metrics.packet_loss_rate > 5.0 || metrics.jitter > 50.0) {
            max_packets = 200;
            max_size    = 30 * 1024 * 1024;  // 30 MB
            min_packets = 50;
        } else if (metrics.packet_loss_rate > 2.0 || metrics.jitter > 20.0) {
            max_packets = 150;
            max_size    = 20 * 1024 * 1024;  // 20 MB
            min_packets = 30;
        } else {
            max_packets = 100;
            max_size    = 15 * 1024 * 1024;  // 15 MB
            min_packets = 10;
        }

        spdlog::debug(
            "Packet queue adapted: max_packets={}, max_size={} MB, "
            "min_packets={}",
            max_packets, max_size / 1024 / 1024, min_packets);
    }

    void set_finished( ) {
        std::lock_guard<std::mutex> lock(mutex);
        finished = true;
        cond_var.notify_all( );
    }

    void clear( ) {
        std::lock_guard<std::mutex> lock(mutex);
        while (!packets.empty( )) {
            AVPacket* pkt = packets.front( );
            packets.pop( );
            av_packet_free(&pkt);
        }
        total_size = 0;
    }

    ~PacketQueue( ) { clear( ); }
};

NetworkMetrics g_network_metrics;

int get_interface_mtu(const char* interface_name) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFMTU, &ifr) < 0) {
        close(sock);
        return -1;
    }

    close(sock);
    return ifr.ifr_mtu;
}

int detect_path_mtu(const char* hostname, int port = 554) {
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(hostname, port_str, &hints, &result) != 0) {
        spdlog::warn("MTU detection: Cannot resolve hostname {}", hostname);
        return 1500;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        freeaddrinfo(result);
        return 1500;
    }

    if (connect(sock, result->ai_addr, result->ai_addrlen) != 0) {
        close(sock);
        freeaddrinfo(result);
        spdlog::warn("MTU detection: Cannot connect to {}:{}", hostname, port);
        return 1500;
    }

    struct sockaddr_in local_addr;
    socklen_t          addr_len = sizeof(local_addr);
    if (getsockname(sock, ( struct sockaddr* ) &local_addr, &addr_len) != 0) {
        close(sock);
        freeaddrinfo(result);
        return 1500;
    }

    close(sock);
    freeaddrinfo(result);

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        spdlog::warn("MTU detection: Cannot get interface addresses");
        return 1500;
    }

    int  mtu                      = 1500;
    char interface_name[IFNAMSIZ] = "";

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        struct sockaddr_in* ifa_addr = ( struct sockaddr_in* ) ifa->ifa_addr;
        if (ifa_addr->sin_addr.s_addr == local_addr.sin_addr.s_addr) {
            strncpy(interface_name, ifa->ifa_name, IFNAMSIZ - 1);
            break;
        }
    }

    freeifaddrs(ifaddr);

    if (strlen(interface_name) > 0) {
        int iface_mtu = get_interface_mtu(interface_name);
        if (iface_mtu > 0) {
            mtu = iface_mtu;
            spdlog::info("MTU detection: Using interface {} with MTU {} bytes",
                         interface_name, mtu);
        } else {
            spdlog::warn(
                "MTU detection: Could not query interface {} MTU, using "
                "default",
                interface_name);
        }
    } else {
        spdlog::warn(
            "MTU detection: Could not determine outgoing interface, using "
            "default MTU");
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo(hostname, port_str, &hints, &result) == 0) {
            if (connect(sock, result->ai_addr, result->ai_addrlen) == 0) {
                int       pmtu   = 0;
                socklen_t optlen = sizeof(pmtu);

                int val = IP_PMTUDISC_DO;
                setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val,
                           sizeof(val));

                if (getsockopt(sock, IPPROTO_IP, IP_MTU, &pmtu, &optlen) == 0 &&
                    pmtu > 0) {
                    mtu = pmtu;
                    spdlog::info("MTU detection: Path MTU to {} is {} bytes",
                                 hostname, mtu);
                }
            }
            freeaddrinfo(result);
        }
        close(sock);
    }

    return mtu;
}

int64_t get_current_time_microseconds( ) {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::high_resolution_clock::now( ).time_since_epoch( ))
        .count( );
}

void update_network_metrics(AVFormatContext* format_context, AVPacket* packet) {
    std::lock_guard<std::mutex> lock(g_network_metrics.metrics_mutex);

    int64_t current_time = get_current_time_microseconds( );

    if (packet && packet->size > 0) {
        g_network_metrics.bytes_received += packet->size;

        /**
         * MTU detection is performed once at startup using proper network
         * probing.
         * Application-level packets over TCP don't directly reveal MTU
         * due to segmentation
         */
    }

    if (g_network_metrics.last_bandwidth_check == 0) {
        g_network_metrics.last_bandwidth_check = current_time;
        g_network_metrics.bytes_last_second = g_network_metrics.bytes_received;
    } else if (current_time - g_network_metrics.last_bandwidth_check >=
               1000000) {  // 1 second
        int64_t bytes_this_second = g_network_metrics.bytes_received -
                                    g_network_metrics.bytes_last_second;
        double bandwidth_bps =
            bytes_this_second * 8.0;  // Convert to bits per second
        double bandwidth_mbps = bandwidth_bps / 1000000.0;

        if (g_network_metrics.bandwidth > 0) {
            g_network_metrics.bandwidth =
                0.8 * g_network_metrics.bandwidth + 0.2 * bandwidth_mbps;
        } else {
            g_network_metrics.bandwidth = bandwidth_mbps;
        }

        g_network_metrics.last_bandwidth_check = current_time;
        g_network_metrics.bytes_last_second = g_network_metrics.bytes_received;
    }

    if (g_network_metrics.last_packet_time > 0) {
        double time_diff_ms =
            (current_time - g_network_metrics.last_packet_time) / 1000.0;
        if (time_diff_ms > 0) {
            g_network_metrics.average_latency =
                0.9 * g_network_metrics.average_latency + 0.1 * time_diff_ms;
        }
    }

    static double  last_inter_packet_delay = 0;
    static int64_t previous_packet_time    = 0;

    if (previous_packet_time > 0) {
        double current_inter_packet_delay =
            (current_time - previous_packet_time) / 1000.0;

        if (last_inter_packet_delay > 0 && current_inter_packet_delay > 0) {
            double delay_variation =
                std::abs(current_inter_packet_delay - last_inter_packet_delay);
            g_network_metrics.jitter =
                0.9 * g_network_metrics.jitter + 0.1 * delay_variation;
        }

        last_inter_packet_delay = current_inter_packet_delay;
    }

    previous_packet_time               = current_time;
    g_network_metrics.last_packet_time = current_time;

    /* Packet loss detection */
    g_network_metrics.total_packets += 1;

    if (g_network_metrics.total_packets > 100 && previous_packet_time > 0) {
        static double expected_interval = 0;
        double        current_interval =
            (current_time - previous_packet_time) / 1000.0;

        if (expected_interval == 0) {
            expected_interval = current_interval;
        } else {
            expected_interval =
                0.95 * expected_interval + 0.05 * current_interval;

            if (current_interval > expected_interval * 5 &&
                expected_interval > 1.0) {
                g_network_metrics.lost_packets++;
                spdlog::debug(
                    "Detected network gap: {:.2f}ms (expected {:.2f}ms)",
                    current_interval, expected_interval);
            }
        }
    }

    if (format_context && format_context->pb) {
        AVIOContext* io = format_context->pb;
        if (io->error != 0) {
            static int last_error_count = 0;
            if (io->error != last_error_count) {
                g_network_metrics.lost_packets++;
                last_error_count = io->error;
            }
        }
    }

    if (g_network_metrics.total_packets > 0) {
        g_network_metrics.packet_loss_rate =
            ( double ) g_network_metrics.lost_packets /
            g_network_metrics.total_packets * 100.0;
    }
}

AdaptiveSettings adapt_settings_based_on_network( ) {
    std::lock_guard<std::mutex> lock(g_network_metrics.metrics_mutex);

    AdaptiveSettings settings;

    if (g_network_metrics.bandwidth > 0.1) {
        double buffer_seconds =
            2.0 + (g_network_metrics.packet_loss_rate / 10.0);
        int64_t calculated_buffer =
            ( int64_t ) (g_network_metrics.bandwidth * 1000000.0 / 8.0 *
                         buffer_seconds);
        settings.buffer_size = ( int ) std::max(
            ( int64_t ) (512 * 1024),
            std::min(calculated_buffer, ( int64_t ) (8 * 1024 * 1024)));
    } else {
        settings.buffer_size = 2 * 1024 * 1024;
    }

    settings.reorder_queue_size =
        ( int ) (50 + (g_network_metrics.packet_loss_rate * 5) +
                 (g_network_metrics.jitter * 0.5));

    int64_t calculated_timeout =
        ( int64_t ) (g_network_metrics.average_latency * 1000 * 10);
    settings.timeout = std::max(( int64_t ) 10000000, calculated_timeout);

    settings.prefer_tcp = true;  // Always prefer TCP for RTSP connections

    spdlog::info("Adaptive settings adjusted based on network conditions:");
    spdlog::info("  Buffer size: {} bytes", settings.buffer_size);
    spdlog::info("  Reorder queue size: {}", settings.reorder_queue_size);
    spdlog::info("  Timeout: {:.2f} seconds", settings.timeout / 1000000.0);
    spdlog::info("  Transport: {}", settings.prefer_tcp ? "TCP" : "UDP");
    spdlog::info("  Current network metrics:");
    spdlog::info("    Network bandwidth: {:.2f} Mbps",
                 g_network_metrics.bandwidth);
    spdlog::info("    Packet loss rate: {:.2f}%",
                 g_network_metrics.packet_loss_rate);
    spdlog::info("    Inter-packet interval: {:.2f} ms",
                 g_network_metrics.average_latency);
    spdlog::info("    Jitter: {:.2f} ms", g_network_metrics.jitter);
    spdlog::info("    MTU size: {} bytes", g_network_metrics.mtu_size);
    spdlog::info("    Total bytes received: {:.2f} MB",
                 g_network_metrics.bytes_received / 1048576.0);

    return settings;
}

bool apply_settings_at_runtime(AVFormatContext*        format_context,
                               const AdaptiveSettings& settings) {
    if (!format_context || !format_context->pb) {
        return false;
    }

    bool changes_made = false;
    int  opt_ret;

    char timeout_str[32];
    snprintf(timeout_str, sizeof(timeout_str), "%lld",
             ( long long ) settings.timeout);

    opt_ret = av_opt_set(format_context->priv_data, "timeout", timeout_str,
                         AV_OPT_SEARCH_CHILDREN);
    if (opt_ret >= 0) {
        spdlog::info("Runtime: Updated timeout to {:.2f}s",
                     settings.timeout / 1000000.0);
        changes_made = true;
    }

    char buffer_size_str[32];
    snprintf(buffer_size_str, sizeof(buffer_size_str), "%d",
             settings.buffer_size);

    opt_ret = av_opt_set(format_context->priv_data, "buffer_size",
                         buffer_size_str, AV_OPT_SEARCH_CHILDREN);
    if (opt_ret >= 0) {
        spdlog::info("Runtime: Updated buffer_size to {} bytes via av_opt_set",
                     settings.buffer_size);
        changes_made = true;
    }

    char reorder_str[32];
    snprintf(reorder_str, sizeof(reorder_str), "%d",
             settings.reorder_queue_size);

    opt_ret = av_opt_set(format_context->priv_data, "reorder_queue_size",
                         reorder_str, AV_OPT_SEARCH_CHILDREN);
    if (opt_ret >= 0) {
        spdlog::info("Runtime: Updated reorder_queue_size to {}",
                     settings.reorder_queue_size);
        changes_made = true;
    }

    return changes_made;
}

bool pause_resume_stream(AVFormatContext* format_context, bool pause) {
    if (!format_context) {
        return false;
    }

    int ret;
    if (pause) {
        ret = av_read_pause(format_context);
        if (ret >= 0) {
            spdlog::info("Runtime: Paused RTSP stream for flow control");
            return true;
        } else {
            spdlog::warn("Runtime: Failed to pause stream (ret={})", ret);
        }
    } else {
        ret = av_read_play(format_context);
        if (ret >= 0) {
            spdlog::info("Runtime: Resumed RTSP stream");
            return true;
        } else {
            spdlog::warn("Runtime: Failed to resume stream (ret={})", ret);
        }
    }
    return false;
}

std::atomic<bool> g_should_stop_monitoring(false);

void network_monitor_thread( ) {
    while (!g_should_stop_monitoring) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));

        {
            std::lock_guard<std::mutex> lock(g_network_metrics.metrics_mutex);
            spdlog::debug(
                "Network monitoring thread: Current metrics - "
                "bandwidth={:.2f}Mbps, loss={:.2f}%, interval={:.2f}ms, "
                "jitter={:.2f}ms, MTU={}",
                g_network_metrics.bandwidth, g_network_metrics.packet_loss_rate,
                g_network_metrics.average_latency, g_network_metrics.jitter,
                g_network_metrics.mtu_size);
        }
    }
}

void packet_reader_thread(AVFormatContext* format_context, PacketQueue* queue,
                          std::atomic<bool>* should_stop) {
    AVPacket packet;
    int      packets_read           = 0;
    int64_t  last_adaptation_time   = get_current_time_microseconds( );
    int64_t  last_flow_control_time = get_current_time_microseconds( );
    bool     stream_paused          = false;

    spdlog::info("Packet reader thread started");

    while (!(*should_stop)) {
        int ret = av_read_frame(format_context, &packet);

        if (ret < 0) {
            if (ret == AVERROR_EOF) {
                spdlog::info("End of stream reached");
            } else {
                char errbuf[1024];
                av_strerror(ret, errbuf, sizeof(errbuf));
                spdlog::warn("Error reading frame: {}", errbuf);
            }
            break;
        }

        update_network_metrics(format_context, &packet);

        queue->push(&packet);
        av_packet_unref(&packet);

        packets_read++;

        if (packets_read % 100 == 0) {
            AdaptiveSettings new_settings = adapt_settings_based_on_network( );

            apply_settings_at_runtime(format_context, new_settings);

            queue->adapt_to_network(g_network_metrics);

            last_adaptation_time = get_current_time_microseconds( );
        }

        int queue_size = queue->size( );
        int queue_min  = queue->min_packets;
        int queue_max  = queue->max_packets;

        {
            std::lock_guard<std::mutex> lock(g_network_metrics.metrics_mutex);

            if (queue_size > queue_max * 0.8) {
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }

            int64_t current_time = get_current_time_microseconds( );
            if (g_network_metrics.packet_loss_rate > 15.0 &&
                current_time - last_flow_control_time >
                    5000000) {  // Every 5 seconds

                if (!stream_paused) {
                    spdlog::warn(
                        "High packet loss ({:.2f}%), pausing stream briefly",
                        g_network_metrics.packet_loss_rate);
                    if (pause_resume_stream(format_context, true)) {
                        stream_paused = true;
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(500));
                    }
                }
                last_flow_control_time = current_time;
            } else if (stream_paused &&
                       g_network_metrics.packet_loss_rate < 5.0) {
                spdlog::info("Network recovered, resuming stream");
                pause_resume_stream(format_context, false);
                stream_paused          = false;
                last_flow_control_time = current_time;
            }

            if (g_network_metrics.jitter > 50.0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            } else if (g_network_metrics.jitter > 20.0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
    }

    if (stream_paused) {
        pause_resume_stream(format_context, false);
    }

    queue->set_finished( );
    spdlog::info("Packet reader thread finished. Read {} packets",
                 packets_read);
}

int main(int argc, char* argv[]) {
    auto console_sink =
        std::make_shared<spdlog::sinks::stdout_color_sink_mt>( );
    console_sink->set_level(spdlog::level::debug);
    console_sink->set_pattern("[%^%l%$] %v");

    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
        "ffplay_clone.log", true);
    file_sink->set_level(spdlog::level::info);

    auto logger = std::make_shared<spdlog::logger>(
        "multi_sink", spdlog::sinks_init_list{console_sink, file_sink});
    spdlog::set_default_logger(logger);
    spdlog::set_level(spdlog::level::debug);

    spdlog::info("FFplay Clone - Adaptive RTSP Player");

    const char* rtsp_url = nullptr;

    if (argc < 2) {
        spdlog::info("Usage: {} <RTSP_URL>", argv[0]);
        spdlog::info("Example: {} rtsp://example.com/stream", argv[0]);
        spdlog::info(
            "No RTSP_URL provided as argument, using test URL for "
            "demonstration");
        rtsp_url =
            "rtsp://demo:demo@ipvmdemo.dyndns.org:5541/onvif-media/"
            "media.amp?profile=profile_1_h264";
    } else {
        rtsp_url = argv[1];
    }

    spdlog::info("Attempting to connect to RTSP stream: {}", rtsp_url);

    std::string url_str(rtsp_url);
    std::string hostname;
    size_t      proto_end = url_str.find("://");
    if (proto_end != std::string::npos) {
        size_t host_start = proto_end + 3;
        size_t at_pos     = url_str.find('@', host_start);
        if (at_pos != std::string::npos) {
            host_start = at_pos + 1;
        }

        size_t host_end = url_str.find_first_of(":/?", host_start);
        if (host_end == std::string::npos) {
            host_end = url_str.length( );
        }
        hostname = url_str.substr(host_start, host_end - host_start);

        spdlog::info("Detecting path MTU to host: {}", hostname);
        int detected_mtu           = detect_path_mtu(hostname.c_str( ));
        g_network_metrics.mtu_size = detected_mtu;
        spdlog::info("Detected path MTU: {} bytes", detected_mtu);
    }

    avformat_network_init( );

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_TIMER)) {
        spdlog::error("Could not initialize SDL - {}", SDL_GetError( ));
        return -1;
    }

    g_network_metrics.packet_loss_rate = 0.0;
    g_network_metrics.average_latency  = 0.0;
    g_network_metrics.bandwidth        = 0.0;
    g_network_metrics.jitter           = 0.0;

    std::thread monitor_thread(network_monitor_thread);

    AVFormatContext* format_context = nullptr;
    AVDictionary*    options        = NULL;

    AdaptiveSettings settings = adapt_settings_based_on_network( );

    av_dict_set(&options, "rtsp_transport", settings.prefer_tcp ? "tcp" : "udp",
                0);
    av_dict_set_int(&options, "buffer_size", settings.buffer_size, 0);
    av_dict_set_int(&options, "reorder_queue_size", settings.reorder_queue_size,
                    0);
    av_dict_set_int(&options, "timeout", settings.timeout, 0);
    av_dict_set_int(&options, "initial_pause", settings.initial_pause, 0);
    av_dict_set(&options, "allowed_media_types", "video",
                0);  // Only video stream
    av_dict_set(&options, "rtsp_flags", "prefer_tcp",
                0);  // Prefer TCP for RTSP

    int ret = avformat_open_input(&format_context, rtsp_url, NULL, &options);

    av_dict_free(&options);

    if (ret < 0) {
        char errbuf[1024];
        av_strerror(ret, errbuf, sizeof(errbuf));
        spdlog::error("Could not open input stream: {}", errbuf);
        spdlog::info(
            "Note: This error can occur due to incorrect credentials, network "
            "issues, or unsupported stream format.");
        spdlog::info("Try checking your RTSP URL and credentials.");
        g_should_stop_monitoring = true;
        monitor_thread.join( );
        SDL_Quit( );
        return -1;
    }

    ret = avformat_find_stream_info(format_context, NULL);
    if (ret < 0) {
        char errbuf[1024];
        av_strerror(ret, errbuf, sizeof(errbuf));
        spdlog::error("Could not find stream information: {}", errbuf);
        avformat_close_input(&format_context);
        g_should_stop_monitoring = true;
        monitor_thread.join( );
        SDL_Quit( );
        return -1;
    }

    spdlog::info("Successfully opened RTSP stream");
    spdlog::info("Number of streams: {}", format_context->nb_streams);

    for (unsigned int i = 0; i < format_context->nb_streams; i++) {
        AVStream*          stream   = format_context->streams[i];
        AVCodecParameters* codecpar = stream->codecpar;

        spdlog::info("Stream {}: ", i);
        switch (codecpar->codec_type) {
            case AVMEDIA_TYPE_VIDEO:
                spdlog::info("  Video - Codec: {} {}x{}",
                             avcodec_get_name(codecpar->codec_id),
                             codecpar->width, codecpar->height);
                break;
            case AVMEDIA_TYPE_AUDIO:
                spdlog::info("  Audio - Codec: {} {}Hz ",
                             avcodec_get_name(codecpar->codec_id),
                             codecpar->sample_rate);
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(60, 26, 100)
                spdlog::info("{}ch", codecpar->ch_layout.nb_channels);
#else
                spdlog::info("{}ch", codecpar->channels);
#endif
                break;
            default:
                spdlog::info("  Other");
                break;
        }
    }

    int                video_stream_index = -1;
    AVCodecParameters* codecpar           = nullptr;
    for (unsigned int i = 0; i < format_context->nb_streams; i++) {
        if (format_context->streams[i]->codecpar->codec_type ==
            AVMEDIA_TYPE_VIDEO) {
            video_stream_index = i;
            codecpar           = format_context->streams[i]->codecpar;
            break;
        }
    }

    if (video_stream_index == -1) {
        spdlog::error("No video stream found");
        avformat_close_input(&format_context);
        g_should_stop_monitoring = true;
        monitor_thread.join( );
        SDL_Quit( );
        return -1;
    }

    const AVCodec* decoder = avcodec_find_decoder(codecpar->codec_id);
    if (!decoder) {
        spdlog::error("Failed to find decoder for codec {}",
                      avcodec_get_name(codecpar->codec_id));
        avformat_close_input(&format_context);
        g_should_stop_monitoring = true;
        monitor_thread.join( );
        SDL_Quit( );
        return -1;
    }

    AVCodecContext* codec_context = avcodec_alloc_context3(decoder);
    if (!codec_context) {
        spdlog::error("Failed to allocate codec context");
        avformat_close_input(&format_context);
        g_should_stop_monitoring = true;
        monitor_thread.join( );
        SDL_Quit( );
        return -1;
    }

    if (avcodec_parameters_to_context(codec_context, codecpar) < 0) {
        spdlog::error("Failed to copy codec parameters to context");
        avcodec_free_context(&codec_context);
        avformat_close_input(&format_context);
        g_should_stop_monitoring = true;
        monitor_thread.join( );
        SDL_Quit( );
        return -1;
    }

    if (avcodec_open2(codec_context, decoder, NULL) < 0) {
        spdlog::error("Failed to open codec");
        avcodec_free_context(&codec_context);
        avformat_close_input(&format_context);
        g_should_stop_monitoring = true;
        monitor_thread.join( );
        SDL_Quit( );
        return -1;
    }

    /* Player specific code -- uses SDL2 on Linux -- available with VCPKG */
    SDL_Window* window = SDL_CreateWindow(
        "FFplay Clone - RTSP Player", SDL_WINDOWPOS_UNDEFINED,
        SDL_WINDOWPOS_UNDEFINED, codecpar->width, codecpar->height,
        SDL_WINDOW_SHOWN | SDL_WINDOW_RESIZABLE);

    if (!window) {
        spdlog::error("Could not create window - {}", SDL_GetError( ));
        avcodec_free_context(&codec_context);
        avformat_close_input(&format_context);
        g_should_stop_monitoring = true;
        monitor_thread.join( );
        SDL_Quit( );
        return -1;
    }

    SDL_Renderer* renderer =
        SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
    if (!renderer) {
        spdlog::error("Could not create renderer - {}", SDL_GetError( ));
        SDL_DestroyWindow(window);
        avcodec_free_context(&codec_context);
        avformat_close_input(&format_context);
        g_should_stop_monitoring = true;
        monitor_thread.join( );
        SDL_Quit( );
        return -1;
    }

    SDL_Texture* texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_YV12,
                                             SDL_TEXTUREACCESS_STREAMING,
                                             codecpar->width, codecpar->height);

    if (!texture) {
        spdlog::error("Could not create texture - {}", SDL_GetError( ));
        SDL_DestroyRenderer(renderer);
        SDL_DestroyWindow(window);
        avcodec_free_context(&codec_context);
        avformat_close_input(&format_context);
        g_should_stop_monitoring = true;
        monitor_thread.join( );
        SDL_Quit( );
        return -1;
    }

    spdlog::info("Created SDL window {}x{} for video playback", codecpar->width,
                 codecpar->height);

    PacketQueue       packet_queue;
    std::atomic<bool> should_stop_reader(false);

    spdlog::info("Starting packet reader thread with adaptive flow control...");
    std::thread reader_thread(packet_reader_thread, format_context,
                              &packet_queue, &should_stop_reader);

    AVFrame* frame             = av_frame_alloc( );
    int      packets_processed = 0;
    int      frames_displayed  = 0;
    bool     quit              = false;
    int64_t  last_stats_time   = get_current_time_microseconds( );

    spdlog::info("Starting video playback with adaptive settings...");

    while (!quit) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            if (event.type == SDL_QUIT) {
                quit = true;
                break;
            }
        }

        if (quit) break;

        AVPacket* packet = packet_queue.pop(100);

        if (!packet) {
            if (packet_queue.finished) {
                spdlog::info("Queue finished, ending playback");
                break;
            }
            continue;
        }

        packets_processed++;

        if (packet->stream_index == video_stream_index) {
            ret = avcodec_send_packet(codec_context, packet);
            if (ret < 0) {
                spdlog::warn("Error sending packet to decoder");
            } else {
                while (ret >= 0) {
                    ret = avcodec_receive_frame(codec_context, frame);
                    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {
                        break;
                    } else if (ret < 0) {
                        spdlog::warn("Error during decoding");
                        break;
                    }

                    SDL_UpdateYUVTexture(texture, NULL, frame->data[0],
                                         frame->linesize[0], frame->data[1],
                                         frame->linesize[1], frame->data[2],
                                         frame->linesize[2]);

                    SDL_RenderClear(renderer);
                    SDL_RenderCopy(renderer, texture, NULL, NULL);
                    SDL_RenderPresent(renderer);

                    frames_displayed++;
                }
            }
        }

        av_packet_free(&packet);

        int64_t current_time = get_current_time_microseconds( );
        if (current_time - last_stats_time > 5000000) {  // Every 5 seconds
            int queue_size = packet_queue.size( );
            spdlog::info(
                "Playback stats: queue_size={}, packets_processed={}, "
                "frames_displayed={}, fps={:.1f}",
                queue_size, packets_processed, frames_displayed,
                frames_displayed / 5.0);
            frames_displayed = 0;
            last_stats_time  = current_time;
        }
    }

    spdlog::info("Video playback ended. Stopping reader thread...");
    should_stop_reader = true;

    if (reader_thread.joinable( )) {
        reader_thread.join( );
    }

    spdlog::info("Processed {} packets total", packets_processed);

    av_frame_free(&frame);
    SDL_DestroyTexture(texture);
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    avcodec_free_context(&codec_context);

    avformat_close_input(&format_context);

    g_should_stop_monitoring = true;
    if (monitor_thread.joinable( )) {
        monitor_thread.join( );
    }

    spdlog::info("FFMPEG and SDL cleaned up successfully");

    SDL_Quit( );

    spdlog::info("Application terminated successfully");

    return 0;
}
