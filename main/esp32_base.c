/**
 * @file esp32_base.c
 * @brief ESP32 WiFi Network Scanner and UDP Server Application
 * 
 * This application provides:
 * - WiFi network scanning functionality
 * - Interactive network selection via serial console
 * - UDP server for receiving and acknowledging messages
 * 
 * The flow is:
 * 1. Initialize WiFi in station mode
 * 2. Scan for available networks
 * 3. Let user select a network and enter password
 * 4. Connect to the selected network
 * 5. Start UDP server once connected
 */

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/ringbuf.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "driver/uart.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>


/*===========================================================================*/
/*                              DEFINITIONS                                   */
/*===========================================================================*/

/** Maximum number of WiFi access points to store from scan results */
#define MAX_AP_COUNT 20

/** Maximum length for WiFi password input */
#define MAX_PASS_LEN 64

/** UDP server listening port */
#define UDP_PORT 3333

/** UDP port for CSI data streaming */
#define UDP_CSI_PORT 3334

/** Size of UDP receive buffer */
#define UDP_RX_BUF_SIZE 256

/** Maximum CSI data length in bytes */
#define MAX_CSI_LEN 128

/** CSI capture rate control (in milliseconds)
 *  Set to 0 for no rate limiting (capture all CSI packets)
 *  Typical values: 10ms = 100Hz, 20ms = 50Hz, 50ms = 20Hz, 100ms = 10Hz
 */
#define CSI_MIN_INTERVAL_MS 20  /* Minimum interval between CSI captures (50 Hz) */

/** Traffic generator interval (in milliseconds)
 *  CSI is only captured when WiFi traffic occurs.
 *  This creates periodic traffic to ensure continuous CSI capture.
 *  Set to 0 to disable traffic generator (rely on external traffic).
 */
#define TRAFFIC_GEN_INTERVAL_MS 50  /* Generate traffic every 50ms (20 Hz) */

/** Default destination IP for CSI streaming (broadcast address)
 *  Set to 0.0.0.0 to use the IP address of the connected AP's gateway
 *  Or configure to a specific IP address (e.g., 192.168.1.100)
 */
#define CSI_DEST_IP_ADDR "255.255.255.255"  /* Broadcast - change as needed */

/** Packet type definitions */
#define PKT_TYPE_HEARTBEAT    0x01
#define PKT_TYPE_DATA         0x02
#define PKT_TYPE_ACK          0x03
#define PKT_TYPE_CSI          0x04

/** Packet magic number for validation */
#define PKT_MAGIC             0xCAFE

/*===========================================================================*/
/*                          STATIC VARIABLES                                  */
/*===========================================================================*/

/** Logging tag for ESP_LOG macros */
static const char *TAG = "WIFI_SCAN";

/** Event group for WiFi connection status signaling */
static EventGroupHandle_t wifi_event_group;

/** Event bit indicating successful WiFi connection */
static const int CONNECTED_BIT = BIT0;

/** Event bit indicating WiFi connection failure */
static const int FAIL_BIT = BIT1;

/** Array to store scanned WiFi access point records */
static wifi_ap_record_t ap_records[MAX_AP_COUNT];

/** Number of access points found during last scan */
static uint16_t ap_count = 0;

/** Packet sequence number (incremented for each packet sent) */
static uint32_t packet_seq = 0;

/** Ring buffer handle for CSI data */
static RingbufHandle_t csi_ringbuf;

/** UDP socket for CSI streaming (initialized in csi_stream_task) */
static int udp_sock = -1;

/** Destination address for CSI UDP packets */
static struct sockaddr_in csi_dest_addr;

/** Last CSI capture timestamp for rate limiting (in microseconds) */
static volatile int64_t last_csi_time = 0;

/** CSI packet counter (for statistics) */
static volatile uint32_t csi_captured_count = 0;
static volatile uint32_t csi_dropped_count = 0;
/**
 * @brief Packet structure for UDP communication
 * 
 * Network byte order (big-endian) is used for multi-byte fields:
 * - magic: Packet validation (0xCAFE)
 * - seq: Packet sequence number
 * - payload_len: Length of payload data
 * 
 * Note: timestamp is in host byte order (microseconds since boot)
 * @note Uses packed struct to ensure no padding bytes between fields
 */
#pragma pack(push, 1)
typedef struct {
    uint16_t magic;         /**< Magic number for packet validation (network byte order) */
    uint8_t version;        /**< Protocol version */
    uint8_t type;           /**< Packet type (PKT_TYPE_*) */
    uint32_t seq;           /**< Sequence number (network byte order) */
    uint64_t timestamp;     /**< Timestamp in microseconds (host byte order) */
    uint16_t payload_len;   /**< Length of payload data in bytes (network byte order) */
    uint8_t payload[];      /**< Variable-length payload data */
} packet_t;
#pragma pack(pop)


typedef struct {
	uint64_t timestamp;
	int8_t rssi;
	uint8_t channel;
	uint8_t len;
	int8_t  data[MAX_CSI_LEN];
} csi_payload_t;
/*===========================================================================*/
/*                       FORWARD DECLARATIONS                                 */
/*===========================================================================*/

/* Forward declarations - needed because functions are called before their definitions */
void udp_server_task(void *pvParameters);
void csi_stream_task(void *pvParameters);
void traffic_generator_task(void *pvParameters);

/*===========================================================================*/
/*                          EVENT HANDLERS                                    */
/*===========================================================================*/

/**
 * @brief WiFi and IP event handler
 * 
 * Handles the following events:
 * - WIFI_EVENT_STA_START: WiFi station mode started
 * - WIFI_EVENT_STA_DISCONNECTED: Disconnected from access point
 * - IP_EVENT_STA_GOT_IP: Successfully obtained IP address
 * 
 * @param arg User-defined argument (unused)
 * @param event_base Event base (WIFI_EVENT or IP_EVENT)
 * @param event_id Specific event identifier
 * @param event_data Event-specific data
 */
static void wifi_event_handler(void *arg, esp_event_base_t event_base, 
                                int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        /* WiFi station interface has started - ready for scanning/connecting */
        ESP_LOGI(TAG, "WiFi station started");
        /* NOTE: UDP server is now started after getting IP (see IP_EVENT_STA_GOT_IP) */
        
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        /* Lost connection to access point */
        ESP_LOGI(TAG, "Disconnected from AP");
        /* Signal failure to any waiting tasks */
        xEventGroupSetBits(wifi_event_group, FAIL_BIT);
        
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        /* Successfully connected and obtained IP address via DHCP */
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        /* Signal successful connection */
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        
        /* Start CSI streaming task */
        xTaskCreatePinnedToCore(
            csi_stream_task,
            "csi_stream",
            4096,
            NULL,
            5,
            NULL,
            1
        );
        
        /* Start traffic generator to ensure continuous CSI capture */
#if TRAFFIC_GEN_INTERVAL_MS > 0
        xTaskCreatePinnedToCore(
            traffic_generator_task,
            "traffic_gen",
            2048,
            NULL,
            4,  /* Lower priority than CSI streaming */
            NULL,
            0   /* Run on Core 0 */
        );
#endif
		
    }
}

/*===========================================================================*/
/*                          UTILITY FUNCTIONS                                 */
/*===========================================================================*/

/**
 * @brief Read a line of input from serial console
 * 
 * Reads characters until newline/carriage return or buffer is full.
 * Echoes characters back to console as they're typed.
 * 
 * @param buffer Pointer to buffer to store the input
 * @param max_len Maximum number of characters to read (including null terminator)
 * @return Number of characters read (excluding null terminator)
 * 
 * @note This function blocks until a complete line is received
 * @note Uses 10ms polling delay to avoid busy-waiting
 */
static int read_line(char *buffer, int max_len)
{
    int i = 0;
    char c;
    
    while (i < max_len - 1) {
        /* Read one character from stdin */
        if (fread(&c, 1, 1, stdin) == 1) {
            /* Check for end of line */
            if (c == '\n' || c == '\r') {
                if (i > 0) break;  /* End of input - got some characters */
                /* Skip leading newlines */
            } else {
                buffer[i++] = c;
                printf("%c", c);  /* Echo character back to terminal */
                fflush(stdout);   /* Ensure immediate display */
            }
        }
        /* Small delay to prevent CPU spinning and allow other tasks to run */
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    buffer[i] = '\0';  /* Null-terminate the string */
    printf("\n");
    return i;
}

/*===========================================================================*/
/*                          WIFI FUNCTIONS                                    */
/*===========================================================================*/

/**
 * @brief Scan for available WiFi networks
 * 
 * Performs an active WiFi scan and stores results in ap_records array.
 * Displays a formatted list of discovered networks to the console.
 * 
 * @note This is a blocking scan - function returns after scan completes
 * @note Results are stored in global ap_records[] and ap_count
 */

/**
 * @brief WiFi CSI callback function
 * 
 * Called from ISR context when CSI data is received.
 * Implements rate limiting to control CSI capture frequency.
 * Copies CSI data to ring buffer for processing by csi_stream_task.
 * 
 * @param ctx User context (unused)
 * @param info Pointer to CSI information structure
 * 
 * @note Rate is controlled by CSI_MIN_INTERVAL_MS define
 * @note Called from ISR context - must be fast and non-blocking
 */
void wifi_csi_cb(void *ctx, wifi_csi_info_t *info)
{
    if (!info || !info->buf || !csi_ringbuf) return;
    
    /* Get current timestamp */
    int64_t now = esp_timer_get_time();
    
    /* Rate limiting: check if enough time has passed since last capture */
#if CSI_MIN_INTERVAL_MS > 0
    int64_t interval_us = CSI_MIN_INTERVAL_MS * 1000;  /* Convert ms to us */
    if ((now - last_csi_time) < interval_us) {
        /* Too soon since last capture - drop this packet */
        csi_dropped_count++;
        return;
    }
#endif
    
    /* Update last capture time */
    last_csi_time = now;
    csi_captured_count++;
    
    /* Allocate space for CSI payload */
    csi_payload_t payload = {0};
    
    /* Fill payload structure */
    payload.timestamp = now;
    payload.rssi      = info->rx_ctrl.rssi;
    payload.channel   = info->rx_ctrl.channel;
    payload.len       = info->len > MAX_CSI_LEN ? MAX_CSI_LEN : info->len;
    
    /* Copy CSI data (note: info->buf contains int8_t CSI data) */
    memcpy(payload.data, info->buf, payload.len);
    
    /* Send to ring buffer - NOSPLIT type copies the data, so local variable is safe */
    BaseType_t ret = xRingbufferSendFromISR(
        csi_ringbuf,
        &payload,
        sizeof(payload),
        NULL
    );
    
    /* Note: If ring buffer is full, the data will be dropped (ret == pdFAIL) */
    if (ret == pdFAIL) {
        csi_dropped_count++;
    }
}
 
static void wifi_scan(void)
{
    /* Configure scan parameters */
    wifi_scan_config_t scan_config = {
        .ssid = NULL,           /* Scan all SSIDs (not targeting specific network) */
        .bssid = NULL,          /* Scan all BSSIDs */
        .channel = 0,           /* Scan all channels */
        .show_hidden = true,    /* Include hidden networks in results */
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,  /* Active scan (faster, sends probe requests) */
        .scan_time.active.min = 100,  /* Minimum time per channel: 100ms */
        .scan_time.active.max = 300,  /* Maximum time per channel: 300ms */
    };

    ESP_LOGI(TAG, "Starting WiFi scan...");
    
    /* Start blocking scan - function returns when scan completes */
    ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));
    
    /* Get scan results - ap_count is input (max records) and output (actual count) */
    ap_count = MAX_AP_COUNT;
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_count, ap_records));
    
    /* Display results in formatted table */
    ESP_LOGI(TAG, "Found %d networks:", ap_count);
    printf("\n===== Available Networks =====\n");
    for (int i = 0; i < ap_count; i++) {
        printf("%2d. %-32s | RSSI: %d | Ch: %d | %s\n",
               i + 1,                                   /* Network number (1-based) */
               ap_records[i].ssid,                      /* Network name */
               ap_records[i].rssi,                      /* Signal strength (dBm, higher is better) */
               ap_records[i].primary,                   /* WiFi channel */
               (ap_records[i].authmode == WIFI_AUTH_OPEN) ? "Open" : "Secured");
    }
    printf("==============================\n\n");
}

/**
 * @brief Connect to a WiFi network
 * 
 * Attempts to connect to the specified network with given credentials.
 * Blocks until connection succeeds, fails, or times out (15 seconds).
 * 
 * @param ssid Network name to connect to
 * @param password Network password (empty string for open networks)
 * @return true if connection successful, false otherwise
 */
static bool wifi_connect(const char *ssid, const char *password)
{
    wifi_config_t wifi_config = {0};  /* Zero-initialize all fields */
    
    /* Copy SSID and password with bounds checking to prevent buffer overflow */
    strncpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, password, sizeof(wifi_config.sta.password) - 1);
    
    ESP_LOGI(TAG, "Connecting to '%s'...", ssid);
    
    /* Apply WiFi configuration and initiate connection */
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_connect());
    
    /* Wait for connection result with 15 second timeout
     * pdTRUE = clear bits on exit
     * pdFALSE = wait for ANY bit (not all bits) */
    EventBits_t bits = xEventGroupWaitBits(wifi_event_group,
                                           CONNECTED_BIT | FAIL_BIT,
                                           pdTRUE, pdFALSE,
                                           pdMS_TO_TICKS(15000));
    
    if (bits & CONNECTED_BIT) {
        ESP_LOGI(TAG, "Successfully connected to '%s'", ssid);
        return true;
    } else {
        ESP_LOGE(TAG, "Failed to connect to '%s'", ssid);
        return false;
    }
}

/**
 * @brief Initialize WiFi subsystem
 * 
 * Performs complete WiFi initialization sequence:
 * 1. Create event group for connection status
 * 2. Initialize NVS (required for WiFi)
 * 3. Initialize network interface
 * 4. Create event loop and register handlers
 * 5. Configure WiFi in station mode
 * 6. Start WiFi
 */
static void wifi_init(void)
{
    /* Create FreeRTOS event group for signaling connection status */
    wifi_event_group = xEventGroupCreate();
    
    /* FIX: Proper NVS initialization with error recovery
     * NVS is required for WiFi calibration data storage */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        /* NVS partition was truncated or version changed - erase and reinitialize */
        ESP_LOGW(TAG, "NVS partition issue, erasing and reinitializing...");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    /* Initialize TCP/IP network interface */
    ESP_ERROR_CHECK(esp_netif_init());
    
    /* Create default event loop for system events */
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    /* Create default WiFi station network interface */
    esp_netif_create_default_wifi_sta();
    
    /* Initialize WiFi driver with default configuration */
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    /* Register event handlers for WiFi and IP events */
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));
    
    /* Set WiFi mode to station (client) and start WiFi */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
	wifi_csi_config_t csi_config = {
		.lltf_en           = true,
		.htltf_en          = true,
		.stbc_htltf2_en    = true,
		.ltf_merge_en      = true,
		.channel_filter_en = false,
		.manu_scale        = false,
		.shift             = false,
	};
	
	ESP_ERROR_CHECK(esp_wifi_set_csi_config(&csi_config));
	ESP_ERROR_CHECK(esp_wifi_set_csi_rx_cb(wifi_csi_cb, NULL));
	ESP_ERROR_CHECK(esp_wifi_set_csi(true));
	
}

/*===========================================================================*/
/*                          TASK FUNCTIONS                                    */
/*===========================================================================*/

/**
 * @brief CSI Streaming Task
 * 
 * Receives CSI data from ring buffer and sends it via UDP.
 * Creates a UDP socket and sends structured packets containing CSI data.
 * 
 * @param pvParameters FreeRTOS task parameters (unused)
 */
void csi_stream_task(void *pvParameters)
{
    /* Calculate required buffer size: packet header + CSI payload */
    const size_t required_buffer_size = sizeof(packet_t) + sizeof(csi_payload_t);
    uint8_t buffer[required_buffer_size + 16];  /* Add some margin for safety */
    
    /* Create UDP socket for sending CSI data */
    udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (udp_sock < 0) {
        ESP_LOGE(TAG, "CSI: Unable to create UDP socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "CSI: UDP socket created for streaming");
    
    /* Configure destination address for CSI packets */
    memset(&csi_dest_addr, 0, sizeof(csi_dest_addr));
    csi_dest_addr.sin_family = AF_INET;
    csi_dest_addr.sin_port = htons(UDP_CSI_PORT);
    
    /* Convert IP address string to network byte order
     * Note: inet_addr returns INADDR_NONE (0xFFFFFFFF) for both errors and 255.255.255.255
     * For broadcast address, handle it directly to avoid ambiguity */
    if (strcmp(CSI_DEST_IP_ADDR, "255.255.255.255") == 0) {
        csi_dest_addr.sin_addr.s_addr = INADDR_BROADCAST;
    } else {
        in_addr_t addr = inet_addr(CSI_DEST_IP_ADDR);
        if (addr == INADDR_NONE) {
            ESP_LOGE(TAG, "CSI: Invalid destination IP address: %s", CSI_DEST_IP_ADDR);
            close(udp_sock);
            udp_sock = -1;
            vTaskDelete(NULL);
            return;
        }
        csi_dest_addr.sin_addr.s_addr = addr;
    }
    
    ESP_LOGI(TAG, "CSI: Streaming to %s:%d (rate limit: %d ms)", 
             CSI_DEST_IP_ADDR, UDP_CSI_PORT, CSI_MIN_INTERVAL_MS);
    
    /* Variables for statistics logging */
    uint32_t sent_count = 0;
    int64_t last_stats_time = esp_timer_get_time();
    const int64_t STATS_INTERVAL_US = 5000000;  /* Log stats every 5 seconds */
    
    /* Main loop: receive CSI data from ring buffer and send via UDP */
    while (1) {
        size_t item_size;
        
        /* Periodic statistics logging */
        int64_t now = esp_timer_get_time();
        if ((now - last_stats_time) >= STATS_INTERVAL_US) {
            float elapsed_sec = (now - last_stats_time) / 1000000.0f;
            ESP_LOGI(TAG, "CSI Stats: sent=%lu, captured=%lu, dropped=%lu, rate=%.1f pkt/s",
                     sent_count, csi_captured_count, csi_dropped_count,
                     sent_count / elapsed_sec);
            sent_count = 0;
            last_stats_time = now;
        }
        
        /* Receive CSI payload from ring buffer (wait up to 100ms) */
        csi_payload_t *payload = (csi_payload_t *)xRingbufferReceive(
            csi_ringbuf,
            &item_size,
            pdMS_TO_TICKS(100)
        );
        
        if (payload) {
            /* Verify received item size matches expected size */
            if (item_size != sizeof(csi_payload_t)) {
                ESP_LOGW(TAG, "CSI: Received item size mismatch (got %d, expected %d)", 
                         item_size, sizeof(csi_payload_t));
                vRingbufferReturnItem(csi_ringbuf, payload);
                continue;
            }
            
            /* Construct packet header */
            packet_t *pkt = (packet_t *)buffer;
            pkt->magic       = htons(PKT_MAGIC);
            pkt->version     = 1;
            pkt->type        = PKT_TYPE_CSI;
            pkt->seq         = htonl(packet_seq++);
            pkt->timestamp   = payload->timestamp;  /* Already in microseconds */
            pkt->payload_len = htons(sizeof(csi_payload_t));
            
            /* Copy CSI payload data into packet */
            memcpy(pkt->payload, payload, sizeof(csi_payload_t));
            
            /* Send packet via UDP */
            int sent = sendto(
                udp_sock,
                buffer,
                required_buffer_size,
                0,
                (struct sockaddr *)&csi_dest_addr,
                sizeof(csi_dest_addr)
            );
            
            if (sent < 0) {
                ESP_LOGE(TAG, "CSI: sendto failed: errno %d", errno);
            } else if (sent != required_buffer_size) {
                ESP_LOGW(TAG, "CSI: Partial send (%d of %d bytes)", sent, required_buffer_size);
            } else {
                sent_count++;  /* Successfully sent */
            }
            
            /* Return the buffer item to the ring buffer */
            vRingbufferReturnItem(csi_ringbuf, payload);
        }
        /* If no data received, loop continues and waits again */
    }
    
    /* Cleanup (unreachable in normal operation) */
    if (udp_sock >= 0) {
        close(udp_sock);
        udp_sock = -1;
    }
    vTaskDelete(NULL);
}

/**
 * @brief Traffic Generator Task
 * 
 * Generates periodic WiFi traffic to ensure continuous CSI capture.
 * CSI data is only captured when WiFi frames are transmitted/received.
 * This task sends small UDP packets to the gateway at regular intervals.
 * 
 * @param pvParameters FreeRTOS task parameters (unused)
 */
void traffic_generator_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Traffic generator started (interval: %d ms)", TRAFFIC_GEN_INTERVAL_MS);
    
    /* Create UDP socket for traffic generation */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Traffic gen: Unable to create socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }
    
    /* Get gateway IP address from network interface */
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info;
    
    if (netif == NULL || esp_netif_get_ip_info(netif, &ip_info) != ESP_OK) {
        ESP_LOGE(TAG, "Traffic gen: Failed to get IP info");
        close(sock);
        vTaskDelete(NULL);
        return;
    }
    
    /* Configure destination - send to gateway */
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = ip_info.gw.addr;  /* Gateway address */
    dest_addr.sin_port = htons(12345);  /* Arbitrary port - traffic just needs to be sent */
    
    char gw_str[16];
    esp_ip4addr_ntoa(&ip_info.gw, gw_str, sizeof(gw_str));
    ESP_LOGI(TAG, "Traffic gen: Sending to gateway %s", gw_str);
    
    /* Small ping packet */
    uint8_t ping_data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint32_t ping_count = 0;
    
    while (1) {
        /* Send small UDP packet to gateway */
        int sent = sendto(
            sock,
            ping_data,
            sizeof(ping_data),
            0,
            (struct sockaddr *)&dest_addr,
            sizeof(dest_addr)
        );
        
        if (sent < 0) {
            /* Don't spam logs on send errors */
            if (ping_count % 100 == 0) {
                ESP_LOGW(TAG, "Traffic gen: sendto failed: errno %d", errno);
            }
        } else {
            ping_count++;
        }
        
        /* Wait for next interval */
        vTaskDelay(pdMS_TO_TICKS(TRAFFIC_GEN_INTERVAL_MS));
    }
    
    close(sock);
    vTaskDelete(NULL);
}

/**
 * @brief UDP Server Task
 * 
 * Creates a UDP socket and listens for incoming messages on UDP_PORT.
 * When a message is received, logs it and sends back "ESP32_ACK" reply.
 * 
 * This task runs indefinitely on the specified core.
 * 
 * @param pvParameters FreeRTOS task parameters (unused)
 * 
 * @note Socket is bound to INADDR_ANY (all interfaces)
 * @note Task self-deletes if socket creation fails
 */
void udp_server_task(void *pvParameters)
{
    char rx_buffer[UDP_RX_BUF_SIZE];  /* Buffer for received data */
    char addr_str[INET_ADDRSTRLEN];   /* Buffer for IP address string (e.g., "192.168.1.1") */

    /* FIX: Corrected syntax - was "struct sockaddr_in_dest_addr" (missing space) */
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;            /* IPv4 address family */
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);  /* Listen on all interfaces */
    dest_addr.sin_port = htons(UDP_PORT);      /* Convert port to network byte order */

    /* Create UDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE("UDP", "Unable to create socket: errno %d", errno);
        vTaskDelete(NULL);  /* Delete this task on failure */
        return;
    }
    ESP_LOGI("UDP", "Socket created successfully");

    /* FIX: Check bind() return value - was ignoring potential errors */
    int err = bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err < 0) {
        ESP_LOGE("UDP", "Socket unable to bind: errno %d", errno);
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI("UDP", "UDP server started on port %d", UDP_PORT);

    /* Main receive loop - runs forever */
    while (1) {
        /* FIX: Corrected syntax - was "struct sockaddr_in_dest_addr" 
         * Also renamed to source_addr for clarity (stores sender's address) */
        struct sockaddr_in source_addr;
        socklen_t socklen = sizeof(source_addr);

        /* Block waiting for incoming UDP packet */
        int len = recvfrom(
            sock,
            rx_buffer,
            sizeof(rx_buffer) - 1,  /* Leave room for null terminator */
            0,                       /* No special flags */
            (struct sockaddr *)&source_addr,
            &socklen
        );
        
        /* FIX: Added error handling for recvfrom() */
        if (len < 0) {
            ESP_LOGE("UDP", "recvfrom failed: errno %d", errno);
            continue;  /* Continue listening despite error */
        }
        
        if (len > 0) {
            /* Null-terminate received data for string operations */
            rx_buffer[len] = '\0';
            
            /* Convert sender's IP address to string format */
            inet_ntoa_r(source_addr.sin_addr, addr_str, sizeof(addr_str) - 1);
            ESP_LOGI("UDP", "Received %d bytes from %s: %s", len, addr_str, rx_buffer);

            /* Send acknowledgment back to sender using structured packet format */
            uint8_t buffer[64];
            packet_t *pkt = (packet_t *)buffer;

            /* Initialize packet header fields (convert to network byte order where needed) */
            pkt->magic = htons(PKT_MAGIC);
            pkt->version = 1;
            pkt->type = PKT_TYPE_HEARTBEAT;
            pkt->seq = htonl(packet_seq++);
            pkt->timestamp = esp_timer_get_time();  /* No byte order conversion for uint64_t on same machine */
            pkt->payload_len = htons(0);  /* No payload for heartbeat */

            /* Calculate total packet size (header + payload) */
            int total_len = sizeof(packet_t);
            uint16_t payload_len = ntohs(pkt->payload_len);  /* Convert back to host byte order for calculation */
            if (payload_len > 0) {
                total_len += payload_len;
            }

            /* Safety check to prevent buffer overflow */
            if (total_len > sizeof(buffer)) {
                ESP_LOGE("UDP", "Packet too large to send");
                continue;
            }
            
            /* Send the packet */
            int sent = sendto(
                sock,
                buffer,          /* Send the buffer containing the packet */
                total_len,       /* Send the calculated total length */
                0,
                (struct sockaddr *)&source_addr,
                sizeof(source_addr)
            );
            
            if (sent < 0) {
                ESP_LOGE("UDP", "sendto failed: errno %d", errno);
            } else {
                ESP_LOGI("UDP", "Sent %d byte packet (seq=%u) to %s", sent, packet_seq - 1, addr_str);
            }
        }
    }
    
    /* Note: This code is unreachable but good practice for cleanup */
    close(sock);
    vTaskDelete(NULL);
}

/**
 * @brief WiFi Selection Task
 * 
 * Interactive task that:
 * 1. Scans for available WiFi networks
 * 2. Displays list to user via serial console
 * 3. Gets user's network selection
 * 4. Prompts for password if network is secured
 * 5. Attempts connection
 * 6. Repeats until successful connection
 * 
 * After successful connection, enters main application loop.
 * 
 * @param pvParameters FreeRTOS task parameters (unused)
 */
void wifi_selection_task(void *pvParameters)
{
    char input[16];               /* Buffer for user input (number or 'r') */
    char password[MAX_PASS_LEN];  /* Buffer for password input */
    int selection;                /* User's network selection number */
    
    while (1) {
        /* Scan for available networks */
        wifi_scan();
        
        if (ap_count == 0) {
            ESP_LOGW(TAG, "No networks found. Retrying in 5 seconds...");
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }
        
        /* Prompt user for network selection */
        printf("Enter network number (1-%d) or 'r' to rescan: ", ap_count);
        fflush(stdout);
        
        read_line(input, sizeof(input));
        
        /* Check for rescan command */
        if (input[0] == 'r' || input[0] == 'R') {
            continue;  /* Go back to scanning */
        }
        
        /* Parse and validate selection */
        selection = atoi(input);
        if (selection < 1 || selection > ap_count) {
            printf("Invalid selection. Please try again.\n");
            continue;
        }
        
        /* Get pointer to selected access point (convert 1-based to 0-based index) */
        wifi_ap_record_t *selected_ap = &ap_records[selection - 1];
        
        /* Get password for secured networks */
        if (selected_ap->authmode != WIFI_AUTH_OPEN) {
            printf("Enter password for '%s': ", selected_ap->ssid);
            fflush(stdout);
            read_line(password, sizeof(password));
        } else {
            password[0] = '\0';  /* Empty password for open networks */
        }
        
        /* Attempt to connect */
        if (wifi_connect((char *)selected_ap->ssid, password)) {
            ESP_LOGI(TAG, "Connection successful! Starting main application...");
            break;  /* Exit selection loop on success */
        } else {
            printf("\nConnection failed. Press any key to try again...\n");
            read_line(input, sizeof(input));  /* Wait for user acknowledgment */
        }
    }
    
    /* ================================================================
     * Main Application Loop
     * ================================================================
     * Add your main application code here.
     * At this point, WiFi is connected and UDP server is running.
     */
    while (1) {
        ESP_LOGI(TAG, "Main task running on core %d", xPortGetCoreID());
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

/*===========================================================================*/
/*                          MAIN ENTRY POINT                                  */
/*===========================================================================*/

/**
 * @brief Application entry point
 * 
 * Called by ESP-IDF after system initialization.
 * Initializes WiFi and starts the WiFi selection task.
 */
void app_main(void)
{
    /* Create ring buffer for CSI data
     * Size: Hold up to 10 CSI payloads to prevent data loss during bursts
     * Type: NOSPLIT ensures each item is stored contiguously */
    const size_t ringbuf_size = 10 * sizeof(csi_payload_t);
    csi_ringbuf = xRingbufferCreate(ringbuf_size, RINGBUF_TYPE_NOSPLIT);
    if (csi_ringbuf == NULL) {
        ESP_LOGE(TAG, "Failed to create CSI ring buffer");
        return;
    }
    ESP_LOGI(TAG, "CSI ring buffer created (%d bytes)", ringbuf_size);
    ESP_LOGI(TAG, "ESP32 WiFi Network Scanner");
    ESP_LOGI(TAG, "===========================");
    
    /* Initialize WiFi subsystem */
    wifi_init();
    
    /* Create WiFi selection task on Core 1
     * Parameters:
     * - Task function: wifi_selection_task
     * - Task name: "wifi_selection" (for debugging)
     * - Stack size: 8192 bytes
     * - Task parameters: NULL
     * - Priority: 5 (medium priority)
     * - Task handle: NULL (not needed)
     * - Core: 1 (leaves Core 0 for WiFi/system tasks)
     */
    xTaskCreatePinnedToCore(
        wifi_selection_task,
        "wifi_selection",
        8192,
        NULL,
        5,
        NULL,
        1
    );
}
