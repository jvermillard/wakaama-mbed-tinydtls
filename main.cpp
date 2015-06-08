#include "mbed.h"
#include "EthernetInterface.h"
#include "mbed/rtc_api.h"
extern "C"
{
    #include "wakaama/liblwm2m.h"
    #include "tinydtls/tinydtls.h"
    #include "tinydtls/dtls.h"
}

extern "C"
{
    extern lwm2m_object_t * get_object_device();
    extern lwm2m_object_t * get_object_firmware();
    extern lwm2m_object_t * get_server_object(int serverId, const char* binding, int lifetime, bool storing);
    extern lwm2m_object_t * get_security_object(int serverId, const char* serverUri, bool isBootstrap);
    extern char * get_server_uri(lwm2m_object_t * objectP, uint16_t serverID);
}
uint8_t device_chage(lwm2m_tlv_t * dataArray, lwm2m_object_t * objectP);

// a linked logical connection to a server
typedef struct _connection_t
{
    struct _connection_t *  next;
    char *                  host;
    int                     port;
    Endpoint                ep;
    session_t *             dtlsSession;
} connection_t;

DigitalOut myled(LED1);

// the server UDP socket
UDPSocket udp;

void ethSetup()
{
    EthernetInterface eth;
    eth.init(); //Use DHCP
    eth.connect();
    printf("IP Address is %s\n", eth.getIPAddress());

    udp.init();
    udp.bind(5683);

    udp.set_blocking(false, 10000);
}

// globals for accessing configuration
lwm2m_context_t * lwm2mH = NULL;
lwm2m_object_t * securityObjP;
lwm2m_object_t * serverObject;
connection_t * connList;

// tinydtls globals 
static dtls_context_t *dtls_context = NULL;

// for now, let's use hardcoded PSK

/* The PSK information for DTLS */
#define PSK_DEFAULT_IDENTITY "Client_identity"
#define PSK_DEFAULT_KEY      "secretPSK"

#define PSK_ID_MAXLEN 256
#define PSK_MAXLEN 256
static unsigned char psk_id[PSK_ID_MAXLEN];
static size_t psk_id_length = 0;
static unsigned char psk_key[PSK_MAXLEN];
static size_t psk_key_length = 0;


/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx,
        const session_t *session,
        dtls_credentials_type_t type,
        const unsigned char *id, size_t id_len,
        unsigned char *result, size_t result_length) {

  printf("getpskinfo\n");
  switch (type) {
  case DTLS_PSK_IDENTITY:

    if (result_length < psk_id_length) {
      printf("cannot set psk_identity -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_id, psk_id_length);
    return psk_id_length;
  case DTLS_PSK_KEY:
    if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0) {
      printf("PSK for unknown id requested, exiting\n");
      return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
    } else if (result_length < psk_key_length) {
      printf("cannot set psk -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_key, psk_key_length);
    return psk_key_length;
  default:
    printf("unsupported request type: %d\n", type);
  }

  return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}

static int
send_to_peer(struct dtls_context_t *ctx,
        session_t *session, uint8 *data, size_t len) {
  printf("sendtopeer\n");

    // find lwm2m connection
    connection_t * connP = connList;
    while(connP != NULL) {
        printf("conn\n");
        if (strcmp(connP->host, session->addr) == 0 && connP->port == session->port)
        {
            printf("found connection\n");
            int bytes = udp.sendTo(connP->ep, (char*)data, len);

            if (-1 == bytes)
            {
                printf("error seding udp datagram\n");
            }
            return bytes;
        }
    }
    return -1;
}


static int
read_from_peer(struct dtls_context_t *ctx, 
          session_t *session, uint8 *data, size_t len) {
    printf("read_from_peer\n");
    size_t i;
    for (i = 0; i < len; i++)
       printf("%c", data[i]);

    connection_t * connP = connList;
    while(connP != NULL) {
        if (strcmp(connP->host, session->addr) == 0 && connP->port == session->port)
        {
            printf("found connection\n");
            lwm2m_handle_packet(lwm2mH, (uint8_t*)data, len, (void*)connP);
            return 0;
        }
    }
    printf("lwm2m session for dtls session not found\n");
    return 0;
}

static dtls_handler_t cb = {
  .write = send_to_peer,
  .read  = read_from_peer,
  .event = NULL,
//#ifdef DTLS_PSK
  .get_psk_info = get_psk_info,
//#endif /* DTLS_PSK */
//#ifdef DTLS_ECC
//  .get_ecdsa_key = get_ecdsa_key,
//  .verify_ecdsa_key = verify_ecdsa_key
//#endif /* DTLS_ECC */
};


/* create a new connection to a server */
static void * prv_connect_server(uint16_t serverID, void * userData)
{
    char * host;
    char * portStr;
    char * ptr;
    int port;
    connection_t * connP = NULL;

    bool dtls;

    printf("Create connection for server %d\n",serverID);

    // need to created a connection to the server identified by server ID
    char* uri = get_server_uri(securityObjP, serverID);

    if (uri == NULL)
    {
        printf("server %d not found in security object\n", serverID);
        return NULL;
    }
    printf("URI: %s\n", uri);

    // parse uri in the form "coaps://[host]:[port]"
    if (0==strncmp(uri, "coaps://", strlen("coaps://"))) {
        host = uri+strlen("coaps://");
        dtls = true;
    }
    else if (0==strncmp(uri, "coap://",  strlen("coap://"))) {
        host = uri+strlen("coap://");
        dtls = false;
    }
    else {
        goto exit;
    }
    portStr = strchr(host, ':');
    if (portStr == NULL) goto exit;
    // split strings
    *portStr = 0;
    portStr++;
    port = strtol(portStr, &ptr, 10);
    if (*ptr != 0) {
        goto exit;
    }

    printf("Trying to connect to LWM2M Server at %s:%d\r\n", host, port);

    //  create a connection
    connP =  (connection_t *)malloc(sizeof(connection_t));
    if (connP == NULL)
    {
        printf("Connection creation fail (malloc)\n");
        goto exit;
    } else {
        connP->port = port;
        connP->host = strdup(host);
        connP->next = connList;
        connP->ep.set_address(connP->host, port);
        if (dtls) {
            // create a tinydtls session
            connP->dtlsSession = (session_t *)malloc(sizeof(session_t));
            connP->dtlsSession->addr = connP->host;
            connP->dtlsSession->port = port;
            // nah wait a bit :D dtls_connect(dtls_context,connP->dtlsSession);
        } else {
			connP->dtlsSession = NULL;
		}

        connList = connP;
        printf("udp connection created\n");
    }
exit:
    free(uri);

    return connP;
}

/* send a buffer to a session*/
static uint8_t prv_buffer_send(void * sessionH,
                               uint8_t * buffer,
                               size_t length,
                               void * userdata)
{
    printf("sending\n");
    connection_t * connP = (connection_t*) sessionH;

    if (connP == NULL)
    {
        printf("#> failed sending %lu bytes, missing connection\r\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    printf("sending to %s\n",connP->ep.get_address());

    if (connP->dtlsSession == NULL)
	{
		printf("send NO_SEC datagram\n");
		if (-1 == udp.sendTo(connP->ep, (char*)buffer, length))
		{
			printf("send error\n");
			return COAP_500_INTERNAL_SERVER_ERROR;
		}
	} else {
		printf("send thru dtls\n");
		
		int res = dtls_write(dtls_context, connP->dtlsSession, (uint8 *)buffer, length);
		if (res != length)
		{
			printf("send dtls error: %d\n", res);
			return COAP_500_INTERNAL_SERVER_ERROR;
		}
	}
    return COAP_NO_ERROR;
}

int main()
{
    int result;

    lwm2m_object_t * objArray[4];

    printf("Start\n");
    ethSetup();

    printf("Initializing tinydtls\n");

    // fake loading of PSK..
    psk_id_length = strlen(PSK_DEFAULT_IDENTITY);
    psk_key_length = strlen(PSK_DEFAULT_KEY);
    memcpy(psk_id, PSK_DEFAULT_IDENTITY, psk_id_length);
    memcpy(psk_key, PSK_DEFAULT_KEY, psk_key_length);
    printf("Init\n");

    dtls_init();
    printf("New context\n");
    dtls_context = dtls_new_context(&lwm2mH);

    if (dtls_context == NULL) {
        printf("error creating the dtls context\n");
    }
    printf("Setting handlers\n");

    dtls_set_handler(dtls_context, &cb);

    if (!dtls_context) {
        printf("can't create dtls_context\n");
        exit(-1);
    }

    printf("Initialazing Wakaama\n");

    // create objects
    objArray[0] = get_security_object(123, "coaps://5.39.83.206:5684", false);
    securityObjP = objArray[0];

    objArray[1] = get_server_object(123, "U", 20, false);
    serverObject = objArray[1];
    objArray[2] = get_object_device();
    objArray[3] = get_object_firmware();

    /*
     * The liblwm2m library is now initialized with the functions that will be in
     * charge of communication
     */
    lwm2mH = lwm2m_init(prv_connect_server, prv_buffer_send, NULL);
    if (NULL == lwm2mH)
    {
        fprintf(stderr, "lwm2m_init() failed\r\n");
        return -1;
    }

    // configure the liblwm2m lib

    result = lwm2m_configure(lwm2mH, "julien", NULL, 4, objArray);

    if (result != 0)
    {
        printf("lwm2m_configure() failed: 0x%X\n", result);
        return -1;
    }

    // start

    result = lwm2m_start(lwm2mH);
    if (result != 0)
    {
        printf("lwm2m_start() failed: 0x%X\n", result);
        return -1;
    }

    // main loop

    while (true) {
        char buffer[1024];
        Endpoint server;

        printf("loop...\n");
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        result = lwm2m_step(lwm2mH, &timeout);
        if (result != 0)
        {
            printf("lwm2m_step error %d\n", result);
        }
        int n = udp.receiveFrom(server, buffer, sizeof(buffer));
        printf("Received packet from: %s of size %d\n", server.get_address(), n);
        if (n>0) {
            // TODO: find connection
            connection_t * connP = connList;
            while(connP != NULL) {
                if (strcmp(connP->host, server.get_address()) == 0)
                {

                    printf("found connection\n");
                    // is it a secure connection?
                    if (connP->dtlsSession != NULL) {
						printf("dtls session\n");
						result = dtls_handle_message(dtls_context, connP->dtlsSession, buffer, n);
						printf("dtls handle message %d\n",result);
					} else {
						printf("nosec session\n");
						lwm2m_handle_packet(lwm2mH, (uint8_t*)buffer, n, (void*)connP);
					}
                    break;
                }
            }

            if (connP == NULL) printf("no connection\n");
        }
    }
}
