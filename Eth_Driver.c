/* **************** Eth_Driver.c **************** */
/*
 * The code herein is: Copyright Pavel Teixeira, 2014
 *
 * This Copyright is retained for the purpose of protecting free
 * redistribution of source.
 *
 *     email:  gal[dot]prime[dot]kr[at]gmail[dot]com
 *
 * The primary maintainer for this code is Pavel Teixeira
 * The CONTRIBUTORS file (distributed with this
 * file) lists those known to have contributed to the source.
 *
 * This code is distributed under Version 2 of the GNU General Public
 * License, which you should have received with the source.
 *
 */
/*
 * Building a Transmitting Network Driver skeleton
 *
 * This skeleton handles with the emission of packets 
 * function, which means that supplys a method for
 * ndo_start_xmit().
 *
 * While you are at it, you may want to add other entry points to see
 * how you may exercise them.
 *
 * Once again, you should be able to exercise it with:
 *
 *   insmod Eth_Driver.ko
 *   ifconfig mynet0 up 192.168.3.197
 *   ping -I mynet0 localhost
 *       or
 *   ping -bI mynet0 192.168.3
 *
 * Make sure your chosen address is not being used by anything else.
 *
 @*/
#include <linux/module.h>			// Recognizes that it's a module.
#include <linux/netdevice.h>		// To use the net features.
#include <linux/init.h>				// Initialize the module.
#include <linux/kernel.h>			// Uses the kernel functions.
#include <linux/skbuff.h>			// Packet manipulations.
#include <linux/etherdevice.h>		// For the device.
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/irqreturn.h>

/* Length definitions */
#define mac_addr_len                    6
#define RX_POLL_WEIGHT					64

/* These are the flags in the statusword */
#define ETH_RX_INTR 0x0001
#define ETH_TX_INTR 0x0002

/* net_device referencing */
static struct net_device *device;
static struct net_device_stats *stats;

/* Functions prototypes up here.*/
void Eth_teardown_pool (struct net_device* dev);
__be16 eth_type_trans(struct sk_buff *skb, struct net_device *dev);
int Eth_start_xmit(struct sk_buff *skb, struct net_device *dev);
void Eth_teardown_pool (struct net_device* dev);
static int Eth_napi_struct_poll(struct napi_struct *napi, int budget);
/* Ading the NAPI interruption structure
 * to the code so the driver can handle
 * the high velocity transmission and 
 * packages.
 */	
static struct napi_struct Eth_napi_struct;

/* priv structure that holds the informations about the device. */
struct eth_priv {
	struct net_device_stats stats;
	int status;
	struct eth_packet* ppool;
	struct eth_packet* rx_queue; /* List of incoming packets */
	int rx_int_enabled;
	int tx_packetlen;
	u8* tx_packetdata;
	struct sk_buff* skb;
	spinlock_t lock;
};

/* Structure that holds the informations about the packets. */
struct eth_packet {
	struct eth_packet* next;
	struct eth_device* dev;
	int datalen;
	u8 data[1500];
};

/* Function to print the status. */
void printline(unsigned char *data, int n) {
	char line[256], entry[16];
	int j;
	strcpy(line,"");
	for (j=0; j < n; j++){
		sprintf(entry, " %2x", data[j]);
		strcat(line, entry);
	}
	pr_info("%s\n", line);
}

/*
* Deal with a transmit timeout.
*/

//void nf10_tx_timeout (struct net_device *dev) {
//	struct nf10_priv *priv = netdev_priv(dev);
//	PDEBUG("Transmit timeout at %ld, latency %ld\n", jiffies,
//		jiffies - dev->trans_start);
	/* Simulates a transmission interrupt to get things moving */
//	priv->status = NF10_TX_INTR;
//	nf10_interrupt(0, dev, NULL);
//	priv->stats.tx_errors++;
//	netif_wake_queue(dev);
//	return;
//}

/*
 * Eth_do_ioctl allows the driver to have Input/Output commands.
 * Missing implementation
 */
static int Eth_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd) {
	pr_info("Eth_do_ioctl(%s)\n", dev->name);
	return -1;
}

static struct net_device_stats *Eth_get_stats(struct net_device *dev)
{
	pr_info("Eth_get_stats(%s)\n", dev->name);
	return stats;
}

/*
 * This is where ifconfig comes down and tells us who we are, etc.
 * We can just ignore this.
 */
static int Eth_config(struct net_device *dev, struct ifmap *map)
{
	pr_info("Eth_config(%s)\n", dev->name);
	if (dev->flags & IFF_UP) {
		return -EBUSY;
	}
	return 0;
}

/*
 * This will allow us to change the device mtu size.
 */
static int Eth_change_mtu(struct net_device *dev, int new_mtu)
{
	unsigned long flags = 0;
	struct eth_priv *priv = netdev_priv(dev);
	spinlock_t *lock = &priv->lock;

	pr_info("Eth_change_mtu(%s)\n", dev->name);

	/* Check ranges */
	if ((new_mtu < 68) || (new_mtu > 10000))	//Remember to see at the hardware documentation the right especification
		return -EINVAL;

	/*
	 * Do anything you need, and accept the value
	 */
	spin_unlock_irqrestore(lock, flags);
	dev->mtu = new_mtu;
	spin_unlock_irqrestore(lock, flags);
	printk (KERN_INFO "New mtu: (%d)", dev->mtu);
	return 0; /* Sucess */
}

/*
 * The open function is called on every time we use the "ifconfig" command
 * and it's allways opened by the kernel and then assign an address to it
 * before the interface can carry packets.
 */
static int Eth_open(struct net_device *dev)
{
	pr_info("Hit: Eth_open(%s)\n", dev->name);

	/* start up the transmission queue */

	netif_start_queue(dev);
	return 0;
}

/*
 * Opposit of Eth_open function
 */
static int Eth_close(struct net_device *dev)
{
	pr_info("Hit: Eth_close(%s)\n", dev->name);

	/* shutdown the transmission queue */

	netif_stop_queue(dev);
	return 0;
}

/*
 * Structure that holds all the options supported by the driver.
 */
static struct net_device_ops ndo = {
	.ndo_open = Eth_open,
	.ndo_stop = Eth_close,
	.ndo_start_xmit = Eth_start_xmit,
	.ndo_do_ioctl = Eth_do_ioctl,
	.ndo_get_stats = Eth_get_stats,
	.ndo_set_config = Eth_config,
	.ndo_change_mtu = Eth_change_mtu,
};

int ng_header(struct sk_buff *skb, struct net_device *dev,
                unsigned short type, const void *daddr, const void *saddr,
                unsigned len) {

	struct ethhdr *eth = (struct ethhdr *)skb_push(skb,ETH_HLEN);

	eth->h_proto = htons(type);
	memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest, daddr ? daddr : dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1] ^= 0x01; /* dest is us xor 1 */
	return (dev->hard_header_len);
}


static void Eth_setup(struct net_device *dev)
{
	//char mac_addr[mac_addr_len+1];
	pr_info("Eth_setup(%s)\n", dev->name);

	/* Fill in the MAC address with a phoney */

	//for (j = 0; j < ETH_ALEN; ++j) {
	//	dev->dev_addr[j] = (char)j;
	//}

	/* request_region(), request_irq(),...
	 *
	 * Assign the hardware address of the board: use "\oSNULx", where
	 * x is  0 or 1. The first byte is '\0' to avoid being a multicast
	 * address (the first byte of multicast addrs is odd).
	 */

    	//mac_addr_len = device->addr_len;

        //memset(mac_addr, 0, mac_addr_len+1);
	//snprintf(&mac_addr, mac_addr_len, "NF%d", 0);
        //memcpy(device->dev_addr, mac_addr, mac_addr_len);



	//memcpy(dev->dev_addr, "\0SNUL0", ETH_LEN);
	//if (dev == device)
	//	dev->dev_addr[ETH_LEN-1]++; /* \OSNUL1 */

	ether_setup(dev);

	dev->netdev_ops = &ndo;
	dev->flags |= IFF_NOARP;
	stats = &dev->stats;

	/*
	 * Just for laughs, let's claim that we've seen 50 collisions.
	 */
	stats->collisions = 50;
}

static int __init Eth_driver_init(void)
{
	int result;
	pr_info("Loading Ethernet network module:....");

	/* Add NAPI structure to the device. */
    /* We just use the only netdevice for implementing polling. */
    netif_napi_add(device, &Eth_napi_struct, Eth_napi_struct_poll, RX_POLL_WEIGHT);

	/* Allocating the net device. */
	device = alloc_netdev(0, "Eth%d", Eth_setup);

	if ((result = register_netdev(device))) {
		printk(KERN_EMERG "Eth: error %i registering  device \"%s\"\n", result, device->name);
		free_netdev(device);
		return -1;
	}
	printk(KERN_INFO "Succeeded in loading %s!\n\n", dev_name(&device->dev));
	return 0;
}

static void __exit Eth_driver_exit(void)
{
	pr_info("Unloading transmitting network module\n\n");
	if (device) {
		unregister_netdev(device);
		printk(KERN_INFO "Device Unregistered...");
		Eth_teardown_pool(device);
		free_netdev(device);
		printk(KERN_INFO "Device's memory fully cleaned...");
	}
	return;
}

void Eth_teardown_pool (struct net_device* dev) {
	struct eth_priv *priv = netdev_priv(dev);
    struct eth_packet *pkt;

    while ((pkt = priv->ppool)) {
		priv->ppool = pkt->next;
        kfree (pkt);
       /* FIXME - in-flight packets ? */
    }
}

/* Structure to manage the pool buffer */
struct eth_packet *Eth_get_tx_buffer(struct net_device *dev) {
	struct eth_priv *priv = netdev_priv(dev);
	unsigned long flags = 0;
	spinlock_t *lock = &priv->lock;
	struct eth_packet *pkt;

	spin_lock_irqsave(lock, flags);
	pkt = priv->ppool;
	priv->ppool = pkt->next;
	if (priv->ppool == NULL) {
		printk(KERN_INFO "Pool empty\n");
		netif_stop_queue(dev);
	}
	spin_unlock_irqrestore(lock, flags);
	return pkt;
} 

/*
* Transmit a packet (low level interface)
*/


int Eth_start_xmit(struct sk_buff *skb, struct net_device *dev) {
	int len;
	char *data, shortpkt[ETH_ZLEN];
	struct eth_priv *priv = netdev_priv(dev);

	data = skb->data;
	len = skb->len;
	if (len < ETH_ZLEN) {
		memset(shortpkt, 0 , ETH_ZLEN);
		memcpy(shortpkt, skb->data, skb->len);
		len = ETH_ZLEN;
		data = shortpkt;
	}
	dev->trans_start = jiffies; /* save the timestamp */

	/* Remember the skb, so we can free it at interrupt time */
	priv->skb = skb;

	/* actual deliver of data is device-specific, and not shown here */
	//nf10_hw_tx(data, len, dev);

	return 0; /* Our simple device can not fail */
}

void Eth_rx(struct net_device *dev, struct eth_packet *pkt) {
	struct sk_buff *skb;
	struct eth_priv * priv = netdev_priv(dev);

	/*
	 * The packet has been retrieved from the transmission
	 * medium. Build ans skb around it, so upper layers can handle it
	 */
	skb = dev_alloc_skb(pkt->datalen + 2); //alocating the buffer for the packet

	/* Checking if the packet allocation process went wrong */
	if (!skb) {
		if (printk_ratelimit())
			printk(KERN_NOTICE "Eth rx: low on mem - packet dropped\n");
		priv->stats.rx_dropped++;
		goto out;
	}
	memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);	//No problems, so we can copy the packet to the buffer.

	/* Write metadata, and then pass to the receive level */
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY;	/* don't check it */
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += pkt->datalen;
	netif_rx(skb);
	out:
		return;
}

void eth_release_buffer(struct eth_packet *pkt) {
	unsigned long flags;
	struct eth_priv *priv = netdev_priv(pkt->dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->ppool;
	priv->ppool = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
	if(netif_queue_stopped(pkt->dev) && pkt->next == NULL)
		netif_wake_queue(pkt->dev);
}

static irqreturn_t Eth_interruption(int irq, void *dev_id, struct pt_regs *regs) {
	int statusword;
	struct eth_priv *priv;
	struct eth_packet *pkt = NULL;

	/*
	 * As usual, check the "device" pointer to be sure it is
	 * really interrupting.
	 * Then assign "struct device *dev".
	 */
	 struct net_device *dev = (struct net_device *)dev_id;
	 /* ... and check with hw if it's really ours */

	 /* paranoid */
	 if(!dev)
	 	return;

	/* Lock the device */
	priv = netdev_priv(dev);
	spin_lock(&priv->lock);

	/* retrieve statusword: real netdevices use I/O instructions */
	statusword = priv->status;
	priv->status = 0;
	if(statusword & ETH_RX_INTR) {
		/* Send it to Eth_rx for handling */
		pkt = priv->rx_queue;
		if(pkt) {
			priv->rx_queue = pkt->next;
			Eth_rx(dev, pkt);
		}
	}
	if (statusword & ETH_TX_INTR) {
		/* a transmission is over: free the skb */
		priv->stats.tx_packets++;
		priv->stats.tx_bytes += priv->tx_packetlen;
		dev_kfree_skb(priv->skb);
	}

	/* Unlock the device and we are done */
	spin_unlock(&priv->lock);
	if (pkt)
		eth_release_buffer(pkt); /* Do this outside the lock! */
		return IRQ_HANDLED;
}

static int Eth_napi_struct_poll (struct napi_struct *napi, int budget) {
	int npackets = 0, quota = min(napi->quota, *budget);
	struct sk_buff *skb;
	struct eth_priv *priv = netdev_priv(napi);
	struct eth_packet *pkt;

	while (npackets < quota && priv->rx_queue) {
		pkt = eth_dequeue_buf(napi);
		skb = dev_alloc_skb(pkt->datalen + 2);
		if(!skb) {
			if (printk_ratelimit())
				printk(KERN_NOTICE "Eth: packet dropped\n");
			priv->stats.rx_dropped++;
			eth_release_buffer(pkt);
			continue;
		}
		memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
		skb->dev = napi;
		skb->protocol = eth_type_trans(skb, napi);
		skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it.*/
		netif_receive_skb(skb);

		/* Maintain stats */
		npackets++;
		priv->stats.rx_packets++;
		priv->stats.rx_bytes += pkt->datalen;
		eth_release_buffer(pkt);
	}
	/* If we processed all packets, we're done; tell the kernel and reenables ints */
	*budget -= npackets;
	napi->quota -= npackets;
	if(!priv->rx_queue) {
		netif_rx_complete(napi);
		eth_rx_ints(dev, 1);
		return 0;
	}
	/* We couldn't process everything */
	return 1;
}


module_init(Eth_driver_init);
module_exit(Eth_driver_exit);

MODULE_AUTHOR("Pavel Teixeira");
MODULE_DESCRIPTION("Ethernet driver");
MODULE_LICENSE("GPL v2");
