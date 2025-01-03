#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tanmay and Asit");
MODULE_DESCRIPTION("Advanced Netfilter-based Kernel Firewall Module");

#define HASH_TABLE_BITS 8         // Updated hash table size to avoid redefinition conflict
#define RATE_LIMIT_TIME 60        // Rate limit in seconds
#define RATE_LIMIT_CONN  100 // Max connections per IP within RATE_LIMIT_TIME

// Define a hash table entry for connection tracking
struct conn_track_entry {
    __be32 ip;
    unsigned int conn_count;
    ktime_t last_time;
    bool rate_limited_logged; // New flag for logging control
    struct hlist_node node;
};

// Declare the connection tracking table
DEFINE_HASHTABLE(conn_table, HASH_TABLE_BITS);

// Declare blocked IPs list
#define MAX_BLOCKED_IPS 5
static __be32 blocked_ips[MAX_BLOCKED_IPS] = {
    htonl((192 << 24) | (168 << 16) | (0 << 8) | 1),  // Example IP 192.168.0.1
    htonl((10 << 24) | (0 << 16) | (2 << 8) | 15),
    htonl((10 << 24) | (0 << 16) | (0 << 8) | 2)      // Example IP 10.0.0.2
    // Add more IPs as needed
};

// Check if IP is blocked
static bool is_ip_blocked(__be32 ip) {
    int i;
    for (i = 0; i < MAX_BLOCKED_IPS; i++) {  // Moved declaration outside the loop
        if (blocked_ips[i] == ip) {
            return true;
        }
    }
    return false;
}

// Function to handle rate limiting
static bool rate_limit(__be32 ip) {
    struct conn_track_entry *entry;
    struct hlist_node *tmp;
    bool allowed = true;
    ktime_t now = ktime_get();

    hash_for_each_possible_safe(conn_table, entry, tmp, node, ip) {
        if (entry->ip == ip) {
            if (ktime_to_ms(ktime_sub(now, entry->last_time)) > (RATE_LIMIT_TIME * 1000)) {
                // Reset connection count and logging flag at the start of a new time window
                entry->conn_count = 1;
                entry->last_time = now;
                entry->rate_limited_logged = false; // Reset log flag
            } else if (++entry->conn_count > RATE_LIMIT_CONN) {
                allowed = false;
                // Only log once per rate-limiting period
                if (!entry->rate_limited_logged) {
                    printk(KERN_INFO "Rate limit exceeded for IP %pI4\n", &entry->ip);
                    entry->rate_limited_logged = true; // Set log flag
                }
            }
            return allowed;
        }
    }

    // If IP not found, create a new entry
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        printk(KERN_ERR "Firewall: Memory allocation for connection entry failed\n");
        return false;
    }
    entry->ip = ip;
    entry->conn_count = 1;
    entry->last_time = now;
    entry->rate_limited_logged = false; // Initialize log flag
    hash_add(conn_table, &entry->node, ip);

    return allowed;
}


// Netfilter hook options
static struct nf_hook_ops netfilter_ops;

// Netfilter hook function
static unsigned int firewall_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    struct iphdr *ip_header;

    // Check if it's an IP packet
    ip_header = ip_hdr(skb);
    if (!ip_header) return NF_ACCEPT;

    // Only check for TCP connections
    if (ip_header->protocol != IPPROTO_TCP) return NF_ACCEPT;

    // Check if the IP is blocked
    if (is_ip_blocked(ip_header->saddr)) {
        printk(KERN_INFO "Firewall: Blocked packet from IP %pI4\n", &ip_header->saddr);
        return NF_DROP;
    }

    // Check if the rate limit is exceeded
    if (!rate_limit(ip_header->saddr)) {
        printk(KERN_INFO "Firewall: Rate limit exceeded for IP %pI4\n", &ip_header->saddr);
        return NF_DROP;
    }

    return NF_ACCEPT;
}

// Module initialization
static int __init firewall_init(void) {
    printk(KERN_INFO "Firewall module loaded\n");

    netfilter_ops.hook = firewall_hook;
    netfilter_ops.pf = PF_INET;
    netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &netfilter_ops);
    return 0;
}

// Module cleanup
static void __exit firewall_exit(void) {
    struct conn_track_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    // Unregister the hook
    nf_unregister_net_hook(&init_net, &netfilter_ops);

    // Clear connection tracking table
    hash_for_each_safe(conn_table, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }

    printk(KERN_INFO "Firewall module unloaded\n");
}

module_init(firewall_init);
module_exit(firewall_exit);
