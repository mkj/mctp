#include <stdint.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/mctp.h>

#include <bpf/bpf_helpers.h>

/* RFC5612 example enterprise number */
static const uint16_t IANA_EXAMPLE = 32473;

/* Made up vendor subtype */
static const uint8_t EXAMPLE_VENDOR_SUBTYPE = 0x50;

static const uint8_t MCTP_TYPE_VENDOR_IANA = 0x7f;

struct mctp_hdr {
    uint8_t ver;
    uint8_t dest;
    uint8_t src;
    uint8_t tag;
};

struct mctp_msg_vendor_iana {
    struct mctp_hdr hdr;

    /* 0x7f */
    uint8_t mctp_type;
    __be32 iana_id;

    uint8_t payload[];
} __attribute__((packed));

SEC("sk_skb")
int filter_mctp_bind(struct __sk_buff *skb)
{
    void* data = (void*)(uint64_t)skb->data;
    void* data_end = (void*)(uint64_t)skb->data_end;

    /* +1 for vendor subtype comparison */
    if (data + sizeof(struct mctp_msg_vendor_iana) + 1 > data_end) {
        /* Too short */
        return 0;
    }

    const struct mctp_msg_vendor_iana *msg = data;
    return msg->mctp_type == MCTP_TYPE_VENDOR_IANA
        && __builtin_bswap32(msg->iana_id) == IANA_EXAMPLE
        && msg->payload[0] != EXAMPLE_VENDOR_SUBTYPE;
}
