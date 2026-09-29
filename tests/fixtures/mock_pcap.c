/* Synthetic libpcap ABI fixture. No sockets, drivers, or real packet capture. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define API __declspec(dllexport)
#else
#define API __attribute__((visibility("default")))
#endif
typedef struct device {struct device *next; char *name,*description; void *addresses; uint32_t flags;} device;
typedef struct header {long seconds,micros; uint32_t caplen,len;} header;
typedef struct program {unsigned int len; void *insns;} program;
typedef struct handle {int consumed,bad;} handle;
static device interface_entry={0,"synthetic0","netKit ABI fixture",0,3};
static int live_handles=0;
static header packet_header={123,456,4,4};
static const unsigned char bytes[]={1,2,3,4};
API int mock_live_handles(void) {return live_handles;}
API const char *pcap_lib_version(void) {return "netKit synthetic pcap fixture";}
API int pcap_findalldevs(device **out,char *error) {(void)error;*out=&interface_entry;return 0;}
API void pcap_freealldevs(device *list) {(void)list;}
API void *pcap_create(const char *name,char *error) {
    handle *h=(handle*)calloc(1,sizeof(handle));(void)error;
    if(h){h->bad=strcmp(name,"invalid-metadata")==0;live_handles++;}return h;
}
API void pcap_close(void *raw) {free(raw);live_handles--;}
API int pcap_set_snaplen(void *h,int v) {(void)h;(void)v;return 0;}
API int pcap_set_promisc(void *h,int v) {(void)h;(void)v;return 0;}
API int pcap_set_timeout(void *h,int v) {(void)h;(void)v;return 0;}
API int pcap_set_buffer_size(void *h,int v) {(void)h;(void)v;return 0;}
API int pcap_set_rfmon(void *h,int v) {(void)h;(void)v;return 0;}
API int pcap_can_set_rfmon(void *h) {(void)h;return 0;}
API int pcap_activate(void *h) {(void)h;return 0;}
API int pcap_datalink(void *h) {(void)h;return 1;}
API char *pcap_geterr(void *h) {(void)h;return "synthetic failure";}
API int pcap_next_ex(void *raw,const header **out,const unsigned char **data) {
    handle *h=(handle*)raw;if(h->consumed++)return 0;
    packet_header.caplen=h->bad?100:4;*out=&packet_header;*data=bytes;return 1;
}
API int pcap_setnonblock(void *h,int enabled,char *error) {(void)h;(void)enabled;(void)error;return 0;}
API int pcap_compile(void *h,program *p,const char *filter,int optimize,uint32_t mask) {
    (void)h;(void)optimize;(void)mask;p->len=0;p->insns=0;return strcmp(filter,"reject")==0?-1:0;
}
API int pcap_setfilter(void *h,program *p) {(void)h;(void)p;return 0;}
API void pcap_freecode(program *p) {(void)p;}
API int pcap_stats(void *h,uint32_t *out) {(void)h;out[0]=10;out[1]=2;out[2]=3;out[3]=4;return 0;}
