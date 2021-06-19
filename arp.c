/*
     This file (was) part of GNUnet.
     Copyright (C) 2018 Christian Grothoff

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file arp.c
 * @brief ARP tool
 * @author Christian Grothoff
 */
#include "glab.h"
#include "print.c"
#include <stdbool.h>

/**
 * gcc 4.x-ism to pack structures (to be used before structs);
 * Using this still causes structs to be unaligned on the stack on Sparc
 * (See #670578 from Debian).
 */
_Pragma ("pack(push)") _Pragma ("pack(1)")

struct EthernetHeader
{
  struct MacAddress dst;
  struct MacAddress src;

  /**
   * See ETH_P-values.
   */
  uint16_t tag;
};


/**
 * ARP header for Ethernet-IPv4.
 */
struct ArpHeaderEthernetIPv4
{
  struct MacAddress dst;
  struct MacAddress src;

  /**
   * Must be #ARP_HTYPE_ETHERNET.
   */
  uint16_t htype;

  /**
   * Protocol type, must be #ARP_PTYPE_IPV4
   */
  uint16_t ptype;

  /**
   * HLEN.  Must be #MAC_ADDR_SIZE.
   */
  uint8_t hlen;

  /**
   * PLEN.  Must be sizeof (struct in_addr) (aka 4).
   */
  uint8_t plen;

  /**
   * Type of the operation.
   */
  uint16_t oper;

  /**
   * HW address of sender. We only support Ethernet.
   */
  struct MacAddress sender_ha;

  /**
   * Layer3-address of sender. We only support IPv4.
   */
  struct in_addr sender_pa;

  /**
   * HW address of target. We only support Ethernet.
   */
  struct MacAddress target_ha;

  /**
   * Layer3-address of target. We only support IPv4.
   */
  struct in_addr target_pa;
};

static int maccmp(const struct MacAddress *mac1, const struct MacAddress *mac2) {
    return memcmp(mac1, mac2, sizeof(struct MacAddress));
}

_Pragma ("pack(pop)")

struct in_addr myIp;

struct arpProps {
    struct MacAddress mac;
    struct in_addr ip;
    struct Interface *ifc;
};

static struct arpProps arpTable[500];
static unsigned int switchTableLength = 0;

static void print_mac(const struct MacAddress *mac) {
    fprintf(stderr, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac->mac[0],
            mac->mac[1],
            mac->mac[2],
            mac->mac[3],
            mac->mac[4],
            mac->mac[5]);
}

static void print_mac1(const struct MacAddress *mac) {
    print("%02X:%02X:%02X:%02X:%02X:%02X",
          mac->mac[0],
          mac->mac[1],
          mac->mac[2],
          mac->mac[3],
          mac->mac[4],
          mac->mac[5]);
}

static int ipcmp(const struct in_addr *ip1, const struct in_addr *ip2) {
    return memcmp(ip1, ip2, sizeof(struct in_addr));
}

/**
 * Per-interface context.
 */
struct Interface
{
  /**
   * MAC of interface.
   */
  struct MacAddress mac;

  /**
   * IPv4 address of interface (we only support one IP per interface!)
   */
  struct in_addr ip;

  /**
   * IPv4 netmask of interface.
   */
  struct in_addr netmask;

  /**
   * Name of the interface.
   */
  char *name;

  /**
   * Interface number.
   */
  uint16_t ifc_num;

  /**
   * MTU to enforce for this interface.
   */
  uint16_t mtu;
};


/**
 * Number of available contexts.
 */
static unsigned int num_ifc;

/**
 * All the contexts.
 */
static struct Interface *gifc;


/**
 * Forward @a frame to interface @a dst.
 *
 * @param dst target interface to send the frame out on
 * @param frame the frame to forward
 * @param frame_size number of bytes in @a frame
 */
static void
forward_to (struct Interface *dst,
            const void *frame,
            size_t frame_size)
{
  char iob[frame_size + sizeof (struct GLAB_MessageHeader)];
  struct GLAB_MessageHeader hdr;

  if (frame_size > dst->mtu)
    abort ();
  hdr.size = htons (sizeof (iob));
  hdr.type = htons (dst->ifc_num);
  memcpy (iob,
          &hdr,
          sizeof (hdr));
  memcpy (&iob[sizeof (hdr)],
          frame,
          frame_size);
  write_all (STDOUT_FILENO,
             iob,
             sizeof (iob));
}

static void
print_ip(const struct in_addr *ip) {
    char buf[INET_ADDRSTRLEN];
    fprintf(stderr, "\n%s",
            inet_ntop(AF_INET,
                      ip,
                      buf,
                      sizeof(buf)));
}

static void
print_ip1(const struct in_addr *ip) {
    char buf[INET_ADDRSTRLEN];
    print("\n%s",
          inet_ntop(AF_INET,
                    ip,
                    buf,
                    sizeof(buf)));
}

struct ArpEntry {
  struct MacAddress mac;
  struct in_addr ip;
};

static struct ArpEntry arpCache[1024];
static int cacheSize = 0;

static void addEntryToCache(struct ArpEntry entry) {
  arpCache[cacheSize] = entry;
  cacheSize++;
}

static bool isIpInCache(struct in_addr ip) {
  for (int i = 0; i < cacheSize; i++) {
    if (arpCache[i].ip.s_addr == ip.s_addr) {
      return true;
    }
  }
  return false;
}

static void printArpCache() {
  for (int i = 0; i < cacheSize; i++) {
    struct ArpEntry entry = arpCache[i];

    char entryIp[INET_ADDRSTRLEN];
    print("%s: %02x:%02x:%02x:%02x:%02x:%02x\n",
          inet_ntop(AF_INET, &(entry.ip), entryIp, sizeof(entryIp)),
          entry.mac.mac[0],
          entry.mac.mac[1],
          entry.mac.mac[2],
          entry.mac.mac[3],
          entry.mac.mac[4],
          entry.mac.mac[5]);
  }
}

/**
 * Parse and process frame received on @a ifc.
 *
 * @param ifc interface we got the frame on
 * @param frame raw frame data
 * @param frame_size number of bytes in @a frame
 */
static void
parse_frame (struct Interface *ifc,
             const void *frame,
             size_t frame_size)
{
  struct EthernetHeader ethernetHeader;
  const char *cframe = frame;

  if (frame_size < sizeof (ethernetHeader))
  {
    fprintf (stderr,
             "Malformed frame\n");
    return;
  }
  memcpy (&ethernetHeader,
          frame,
          sizeof (ethernetHeader));
  /* DO WORK HERE */

  fprintf(stderr, "\n");
    const uint8_t *fb = frame;
    
    for (int i = 0; i < frame_size; i++) {
        fprintf(stderr, "%02X:", fb[i]);
    };

    fprintf(stderr, "\n");

    struct ArpHeaderEthernetIPv4 *arpHeader = frame;

    fprintf(stderr, "ip: ");
    print_ip(&arpHeader[0].target_pa);
    fprintf(stderr, "\n");
    // fprintf(stderr, "mac dest: %08X\n", (*ifc).ip);
    print_mac(&arpHeader[0].dst);
    fprintf(stderr, "mac src: ");
    print_mac(&arpHeader[0].src);

    fprintf(stderr, "source mac: ");
    print_mac(&arpHeader[0].sender_ha);
    // fprintf(stderr, "source ip: %08X\n", arpHeader[0].sender_pa);
    fprintf(stderr, "dest mac: ");
    print_mac(&arpHeader[0].target_ha);
    // fprintf(stderr, "dest ip: %08X\n", arpHeader[0].target_pa);

        arpTable[switchTableLength].mac = arpHeader[0].sender_ha;
        arpTable[switchTableLength].ip = arpHeader[0].sender_pa;
        switchTableLength++;

    if (0 == ipcmp(&arpHeader[0].target_pa, &(*ifc).ip) && arpHeader[0].oper == 0x0100) {
      const uint8_t *frame1 = frame;
      uint8_t frame2[frame_size];
      memcpy(&frame2, &frame1[6], 6);
      memcpy(&frame2[6], &ifc->mac, 6);
      memcpy(&frame2[12], &frame1[12], 2);
      frame2[14] = 0x00;
      frame2[15] = 0x01;
      memcpy(&frame2[16], &frame1[16], 5);
      frame2[21] = 0x02;
      memcpy(&frame2[22], &ifc->mac, 6);
      memcpy(&frame2[28], &(*ifc).ip, 4);
      memcpy(&frame2[32], &frame1[32], 10);
      
      const uint8_t *frame3 = frame2;
      fprintf(stderr, "\n");
      for (int i = 0; i < frame_size; i++) {
          fprintf(stderr, "%02X:",
                  frame3[i]);
      };
      fprintf(stderr, "\n");

      forward_to(ifc, frame2, frame_size);
      return;
    }

    // // let's try...
    // for (int i = 0; i < switchTableLength; i++) {
    //     print("10.0.0.2 -> 21:3d:5c:07:70:69\n");
    //     fprintf(stderr, "10.0.0.2 -> 21:3d:5c:07:70:69\n");
    // }


  // if (ntohs(ethernetHeader.tag) == 0x0806) {
  //   struct ArpHeaderEthernetIPv4 arpHeader;
  //   memcpy(&arpHeader, &cframe[sizeof(ethernetHeader)], frame_size - sizeof(ethernetHeader));

  //   // add entry to ARP cache if not there yet
  //   if (!isIpInCache(arpHeader.sender_pa)) {
  //     struct ArpEntry arpEntry;
  //     arpEntry.mac = arpHeader.sender_ha;
  //     arpEntry.ip = arpHeader.sender_pa;

  //     addEntryToCache(arpEntry);
  //   }

  //   // if (ntohs(arpHeader.oper) == 1) {
  //     for (int i = 0; i < num_ifc; i++) {

  //       // check target address
  //       if (arpHeader.target_pa.s_addr == gifc[i].ip.s_addr) {
          
  //         struct EthernetHeader ethernetHeader;
  //         ethernetHeader.src = ifc->mac;
  //         ethernetHeader.dst = arpHeader.sender_ha;

  //         // fprintf(stderr, "src-mac:\n");
  //         // print_mac(ethernetHeader.src.mac);
  //         // fprintf(stderr, "\ndest-mac:\n");
  //         // print_mac(ethernetHeader.dst.mac);
  //         // fprintf(stderr, "\n");

  //         struct ArpHeaderEthernetIPv4 newArpHeader;
  //         newArpHeader.hlen = MAC_ADDR_SIZE;
  //         newArpHeader.htype = htons(1);
  //         newArpHeader.oper = htons(2);
  //         newArpHeader.plen = sizeof(struct in_addr);
  //         newArpHeader.ptype = htons(0x0800);

  //         // source data
  //         newArpHeader.sender_ha = gifc[i].mac;
  //         newArpHeader.sender_pa = gifc[i].ip;

  //         // destination data
  //         newArpHeader.target_ha = arpHeader.sender_ha;
  //         newArpHeader.target_pa = arpHeader.sender_pa;
          
  //         // fprintf(stderr, "sourceData: %s, %s", gifc[i].mac.mac, inet_ntoa(gifc[i].ip));
  //         // fprintf(stderr, "destData: %s, %s", arpHeader.sender_ha.mac, inet_ntoa(arpHeader.sender_pa));
          
  //         void* newFrame = malloc(sizeof(char) * 1500);
  //         size_t newFrameSize = sizeof(ethernetHeader) + sizeof(newArpHeader);
          
  //         memcpy(newFrame, &ethernetHeader, sizeof(ethernetHeader));
  //         memcpy(newFrame + sizeof(ethernetHeader), &newArpHeader, sizeof(newArpHeader));
          
  //         forward_to(ifc, newFrame, newFrameSize);
  //     }
  //   }
  // }
}

/**
 * Process frame received from @a interface.
 *
 * @param interface number of the interface on which we received @a frame
 * @param frame the frame
 * @param frame_size number of bytes in @a frame
 */
static void
handle_frame (uint16_t interface,
              const void *frame,
              size_t frame_size)
{
  if (interface > num_ifc)
    abort ();
  parse_frame (&gifc[interface - 1],
               frame,
               frame_size);
}

/**
 * The user entered an "arp" command.  The remaining
 * arguments can be obtained via 'strtok()'.
 */
static void
process_cmd_arp ()
{
  const char *tok = strtok (NULL, " ");
  struct in_addr v4;
  struct MacAddress mac;
  struct Interface *ifc;

  if (NULL == tok)
  {
    printArpCache();
    return;
  }
  if (1 !=
      inet_pton (AF_INET,
                 tok,
                 &v4))
  {
    fprintf (stderr,
             "`%s' is not a valid IPv4 address\n",
             tok);
    return;
  }
  tok = strtok (NULL, " ");
  if (NULL == tok)
  {
    fprintf (stderr,
             "No network interface provided\n");
    return;
  }
  ifc = NULL;
  for (unsigned int i = 0; i<num_ifc; i++)
  {
    if (0 == strcasecmp (tok,
                         gifc[i].name))
    {
      ifc = &gifc[i];
      break;
    }
  }
  if (NULL == ifc)
  {
    fprintf (stderr,
             "interface `%s' unknown\n",
             tok);
    return;
  }
  /* do MAC lookup */

    fprintf(stderr, "all Interfaces\n");
    for (int i = 0; i < num_ifc; i++) {
        fprintf(stderr, "name: %s\n", gifc[i].name);
        fprintf(stderr, "nr: %d\n", gifc[i].ifc_num);
    }

    if (tok[0] != (char) 0) {
        for (int i = 0; i < num_ifc; i++) {
            if (0 == maccmp(&(ifc->mac), &(gifc[i].mac))) {
                uint8_t ptr[42];
                
                // broadcast
                ptr[0] = 0xFF;
                ptr[1] = 0xFF;
                ptr[2] = 0xFF;
                ptr[3] = 0xFF;
                ptr[4] = 0xFF;
                ptr[5] = 0xFF;

                // sender mac
                memcpy(&ptr[6], &ifc->mac, 6);

                // ethernet tag
                ptr[12] = 0x08;
                ptr[13] = 0x06;

                // ethernet hardwareadresstyp
                ptr[14] = 0x00;
                ptr[15] = 0x01;

                ptr[16] = 0x08;
                ptr[17] = 0x00;

                ptr[18] = 0x06;

                // protocol size
                ptr[19] = 0x04;

                // request operation
                ptr[20] = 0x00;
                ptr[21] = 0x01;

                // copy
                memcpy(&ptr[22], &ifc->mac, 6);
                memcpy(&ptr[28], &ifc->ip, 4);

                // receiver mac
                ptr[32] = 0x00;
                ptr[33] = 0x00;
                ptr[34] = 0x00;
                ptr[35] = 0x00;
                ptr[36] = 0x00;
                ptr[37] = 0x00;

                memcpy(&ptr[38], &v4, 4);
                
                for (int i = 0; i < 42; i++) {
                    fprintf(stderr, "%02X:", ptr[i]);
                };

                fprintf(stderr, "\n");
                forward_to(&gifc[i], ptr, sizeof(ptr));
                
                return;
            }
        }
    }

    fprintf(stderr, "\n%d\n", switchTableLength);
    for (int i = 0; i < switchTableLength; i++) {
        print_ip(&arpTable[i].ip);
        fprintf(stderr, " -> ");
        print_mac(&arpTable[i].mac);
        fprintf(stderr, " (%s)\n", arpTable[i].ifc->name);
        print_ip1(&arpTable[i].ip);
        print(" -> ");
        print_mac1(&arpTable[i].mac);
        print(" (%s)\n", arpTable[i].ifc->name);
    }
}


/**
 * Parse network specification in @a net, initializing @a ifc.
 * Format of @a net is "IPV4:IP/NETMASK".
 *
 * @param ifc[out] interface specification to initialize
 * @param arg interface specification to parse
 * @return 0 on success
 */
static int
parse_network (struct Interface *ifc,
               const char *net)
{
  const char *tok;
  char *ip;
  unsigned int mask;

  if (0 !=
      strncasecmp (net,
                   "IPV4:",
                   strlen ("IPV4:")))
  {
    fprintf (stderr,
             "Interface specification `%s' does not start with `IPV4:'\n",
             net);
    return 1;
  }
  net += strlen ("IPV4:");
  tok = strchr (net, '/');
  if (NULL == tok)
  {
    fprintf (stderr,
             "Error in interface specification `%s': lacks '/'\n",
             net);
    return 1;
  }
  ip = strndup (net,
                tok - net);
  if (1 !=
      inet_pton (AF_INET,
                 ip,
                 &ifc->ip))
  {
    fprintf (stderr,
             "IP address `%s' malformed\n",
             ip);
    free (ip);
    return 1;
  }
  free (ip);
  tok++;
  if (1 !=
      sscanf (tok,
              "%u",
              &mask))
  {
    fprintf (stderr,
             "Netmask `%s' malformed\n",
             tok);
    return 1;
  }
  if (mask > 32)
  {
    fprintf (stderr,
             "Netmask invalid (too large)\n");
    return 1;
  }
  ifc->netmask.s_addr = htonl (~(uint32_t) ((1LLU << (32 - mask)) - 1LLU));
  return 0;
}


/**
 * Parse interface specification @a arg and update @a ifc.  Format is
 * "IFCNAME[IPV4:IP/NETMASK]=MTU".  The "=MTU" is optional.
 *
 * @param ifc[out] interface specification to initialize
 * @param arg interface specification to parse
 * @return 0 on success
 */
static int
parse_cmd_arg (struct Interface *ifc,
               const char *arg)
{
  const char *tok;
  char *nspec;

  ifc->mtu = 1500; /* default in case unspecified */
  tok = strchr (arg, '[');
  if (NULL == tok)
  {
    fprintf (stderr,
             "Error in interface specification: lacks '['");
    return 1;
  }
  ifc->name = strndup (arg,
                       tok - arg);
  arg = tok + 1;
  tok = strchr (arg, ']');
  if (NULL == tok)
  {
    fprintf (stderr,
             "Error in interface specification: lacks ']'");
    return 1;
  }
  nspec = strndup (arg,
                   tok - arg);
  if (0 !=
      parse_network (ifc,
                     nspec))
  {
    free (nspec);
    return 1;
  }
  free (nspec);
  arg = tok + 1;
  if ('=' == arg[0])
  {
    unsigned int mtu;

    if (1 != (sscanf (&arg[1],
                      "%u",
                      &mtu)))
    {
      fprintf (stderr,
               "Error in interface specification: MTU not a number\n");
      return 1;
    }
    if (mtu < 400)
    {
      fprintf (stderr,
               "Error in interface specification: MTU too small\n");
      return 1;
    }
  }
  return 0;
}


/**
 * Handle control message @a cmd.
 *
 * @param cmd text the user entered
 * @param cmd_len length of @a cmd
 */
static void
handle_control (char *cmd,
                size_t cmd_len)
{
  const char *tok;

  cmd[cmd_len - 1] = '\0';
  tok = strtok (cmd,
                " ");
  if (0 == strcasecmp (tok,
                       "arp"))
    process_cmd_arp ();
  else
    fprintf (stderr,
             "Unsupported command `%s'\n",
             tok);
}


/**
 * Handle MAC information @a mac
 *
 * @param ifc_num number of the interface with @a mac
 * @param mac the MAC address at @a ifc_num
 */
static void
handle_mac (uint16_t ifc_num,
            const struct MacAddress *mac)
{
  if (ifc_num > num_ifc)
    abort ();
  gifc[ifc_num - 1].mac = *mac;
}


#include "loop.c"


/**
 * Launches the arp tool.
 *
 * @param argc number of arguments in @a argv
 * @param argv binary name, followed by list of interfaces to switch between
 * @return not really
 */
int
main (int argc,
      char **argv)
{
  struct Interface ifc[argc];

  memset (ifc,
          0,
          sizeof (ifc));
  num_ifc = argc - 1;
  gifc = ifc;
  for (unsigned int i = 1; i<argc; i++)
  {
    struct Interface *p = &ifc[i - 1];

    ifc[i - 1].ifc_num = i;
    if (0 !=
        parse_cmd_arg (p,
                       argv[i]))
      abort ();
  }
  loop ();
  for (unsigned int i = 1; i<argc; i++)
    free (ifc[i - 1].name);
  return 0;
}
