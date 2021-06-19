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
 * @file vswitch.c
 * @brief Ethernet switch
 * @author Christian Grothoff
 */
#include "glab.h"
#include "print.c"
#include "stdbool.h"

/**
 * Maximum number of VLANs supported per interface.
 * (and also by the 802.1Q standard tag).
 */
#define MAX_VLANS 4092

/**
 * Value used to indicate "no VLAN" (or no more VLANs).
 */
#define NO_VLAN (-1)

/**
 * Which VLAN should we assume for untagged frames on
 * interfaces without any specified tag?
 */
#define DEFAULT_VLAN 0

/**
 * gcc 4.x-ism to pack structures (to be used before structs);
 * Using this still causes structs to be unaligned on the stack on Sparc
 * (See #670578 from Debian).
 */
_Pragma("pack(push)") _Pragma("pack(1)")

struct EthernetHeader
{
  struct MacAddress dst;
  struct MacAddress src;
  uint16_t tag;
  uint16_t vlanId;
};

struct SwitchCache {
    struct Interface *interface;
    struct MacAddress macAddress;
};

static struct SwitchCache switchCache[500];
static int switchTableIndex = 0;

static void printMac(struct MacAddress *mac) {
  fprintf(stderr,
          "%02X:%02X:%02X:%02X:%02X:%02X:",
          mac->mac[0],
          mac->mac[1],
          mac->mac[2],
          mac->mac[3],
          mac->mac[4],
          mac->mac[5]);
}

/**
 * Compare two MacAddresses
 * @param macAddress1
 * @param macAddress2
 * @return
 */
static int maccmp (const struct MacAddress *macAddress1, const struct MacAddress *macAddress2){
    return memcmp(macAddress1, macAddress2, sizeof(struct MacAddress));
}

/**
 * IEEE 802.1Q header.
 */
struct Q
{
  uint16_t tpid; /* must be #ETH_802_1Q_TAG */
  uint16_t tci;
};

_Pragma("pack(pop)")


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
   * Number of this interface.
   */
  uint16_t ifc_num;

  /**
   * Name of the network interface, i.e. "eth0".
   */
  char *ifc_name;

  /**
   * Which tagged VLANs does this interface participate in?
   * Array terminated by #NO_VLAN entry.
   */
  int16_t tagged_vlans[MAX_VLANS + 1];

  /**
   * Which untagged VLAN does this interface participate in?
   * #NO_VLAN for none.
   */
  int16_t untagged_vlan;

};

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

  hdr.size = htons (sizeof(iob));
  hdr.type = htons (dst->ifc_num);
  memcpy (iob,
	  &hdr,
	  sizeof(hdr));
  memcpy (&iob[sizeof (hdr)],
	  frame,
	  frame_size);
  write_all (STDOUT_FILENO,
	     iob,
	     sizeof(iob));
}

/**
 * Number of available contexts.
 */
static unsigned int num_ifc;

/**
 * All the contexts.
 */
static struct Interface *gifc;

static void
print_frame(uint16_t interface,
            const void *frame,
            size_t frame_size) {
    const uint8_t *frame1 = frame;
    unsigned int index;

    fprintf(stderr, "\n");
    for (index = 0; index < frame_size; index++) {
        fprintf(stderr, "%02X:",
                frame1[index]);
    };
    fprintf(stderr, "\n");
    fprintf(stderr, "frame_size: %lu", frame_size);
    fprintf(stderr, "source: ");

    for (index = 0; index < 6; index++) {
        fprintf(stderr, "%02X:", frame1[index]);
    };

    fprintf(stderr, " destination: ");
    for (index = 6; index < 12; index++) {
        fprintf(stderr, "%02X:", frame1[index]);
    };

    fprintf(stderr, " payload: ");
    for (index = 12; index < 20; index++) {
        fprintf(stderr, "%02X:", frame1[index]);
    };

    fprintf(stderr, " fsc: ");
    for (index = frame_size - 4; index < frame_size; index++) {
        fprintf(stderr, "%02X:", frame1[index]);
    };

    fprintf(stderr, "\n");
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
  const uint8_t *framec = frame;
  struct EthernetHeader ethernetHeader;

  if (frame_size < sizeof (ethernetHeader))
  {
    fprintf (stderr,
	     "Malformed frame\n");
    return;
  }
  memcpy (&ethernetHeader,
	  frame,
	  sizeof (ethernetHeader));
  /* DO work here! */

  ethernetHeader.vlanId = htons(ethernetHeader.vlanId);
  for (int i = 0; ifc->tagged_vlans[i] != NO_VLAN; i++) {
    fprintf(stderr, "tagged_vlans: %04X\n", ifc->tagged_vlans[i]);
  }

  fprintf(stderr, "ethernet header tag: %04X\n", ethernetHeader.tag);
  fprintf(stderr, "ethernet header vlanId: %04X\n", ethernetHeader.vlanId);

  for (int i = 0; i < num_ifc; i++) {
    fprintf(stderr, "ifc_name: %s\n", gifc[i].ifc_name);
    fprintf(stderr, "ifc_num: %d\n", gifc[i].ifc_num);
    fprintf(stderr, "untagged_vlan: %04X\n", gifc[i].untagged_vlan);

    for (int j = 0; gifc[i].tagged_vlans[j] != NO_VLAN; j++) {
      fprintf(stderr, "tagged_vlans: %04X\n", gifc[i].tagged_vlans[j]);
    }
  }

  if (ethernetHeader.tag == 0x0081) {
    for (int i = 0; ifc->tagged_vlans[i] != ethernetHeader.vlanId; i++) {
      if (ifc -> tagged_vlans[i] == NO_VLAN) {
        return;
      }
    }

    if (ifc -> untagged_vlan != NO_VLAN) {
      return;
    }
  }
  else {
    if (ifc -> untagged_vlan == NO_VLAN) {
      return;
    }
  }

  bool foundEntry = false;
  for (int i = 0; i < switchTableIndex; i++){
    if (0 == maccmp(&switchCache[i].macAddress, &ethernetHeader.src)) {
      foundEntry = true;
      switchCache[i].interface = ifc;
    }
  }

  if (!foundEntry && switchTableIndex < 500)
  {
    switchCache[switchTableIndex].interface = ifc;
    switchCache[switchTableIndex].macAddress = ethernetHeader.src;
    switchTableIndex++;
  }

  fprintf(stderr, "ethernetHeader dst:\n");
  printMac(&ethernetHeader.dst);
  fprintf(stderr, "\n");

  for (int i = 0; i < switchTableIndex; i++) {
    if (0 == maccmp(&ethernetHeader.dst, &switchCache[i].macAddress)) {
      if (ethernetHeader.tag == htons(0x8100)) {
        if (ethernetHeader.vlanId == switchCache[i].interface -> untagged_vlan) {
          const uint8_t *frame1 = frame;
          uint8_t frame2[frame_size - 4];
          memcpy(&frame2, &frame1, 12);
          memcpy(&frame2[12], &frame1[16], frame_size - 12);
          forward_to(switchCache[i].interface, frame2, sizeof(frame2));
          return;
        }
        else {
          for (int j = 0; switchCache[i].interface->tagged_vlans[j] != ethernetHeader.vlanId; j++) {
            if (switchCache[i].interface -> tagged_vlans[j] == NO_VLAN) {
              return;
            }
          }

          forward_to(switchCache[i].interface, frame, frame_size);
          return;
        }
      }
      else {
        if (ifc -> untagged_vlan == switchCache[i].interface -> untagged_vlan) {
          forward_to(switchCache[i].interface, frame, frame_size);
          return;
        }
        else {
          for (int j = 0; switchCache[i].interface->tagged_vlans[j] != ifc->untagged_vlan; j++) {
            if (switchCache[i].interface -> tagged_vlans[j] == NO_VLAN) {
              return;
            }
          }

          const uint8_t *frame1 = frame;
          uint8_t frame2[frame_size + 4];
          struct Q q = {htons(0x8100), ifc->untagged_vlan};

          memcpy(&frame2, frame1, 12);
          memcpy(&frame2[12], &q, sizeof(struct Q));
          memcpy(&frame2[16], &frame1[12], frame_size - 16);

          forward_to(switchCache[i].interface, frame1, sizeof(frame1));
          return;
        }
      }
    }
  }

  for (int i = 0; i < num_ifc; i++) {
    if (0 != maccmp(&ifc->mac, &gifc[i].mac)) {
      if (ethernetHeader.tag == htons(0x8100)) {
        if (ethernetHeader.vlanId == gifc[i].untagged_vlan) {
          const uint8_t *frame1 = frame;
          uint8_t frame2[frame_size - 4];

          print_frame(gifc[i].ifc_num, frame, frame_size);

          memcpy(&frame2, frame, 12);
          memcpy(&frame2[12], &frame[16], frame_size - 12);
          struct EthernetHeader ethernetHeader1;
          
          forward_to(&gifc[i], frame2, sizeof(frame2));
        }
        else {
          bool doSendFrame = true;
          for (int j = 0; gifc[i].tagged_vlans[j] != ethernetHeader.vlanId; j++) {
            if (gifc[i].tagged_vlans[j] == NO_VLAN) {
              doSendFrame = false;
              break;
            }
          }

          if (doSendFrame) {
            const uint8_t *frame1 = frame;
            uint8_t frame2[frame_size + 4];
            struct Q q = {htons(0x8100), htons(ifc->untagged_vlan)};

            memcpy(&frame2[16], &frame1[12], frame_size - 16);
            forward_to(&gifc[i], frame, frame_size);
          }
        }
      }
      else {
        if (ifc-> untagged_vlan == gifc[i].untagged_vlan) {
          printMac(&gifc[i].mac);
          forward_to(&gifc[i], frame, frame_size);
        }
        else {
          bool doSendFrame = true;
          for (int j = 0; gifc[i].tagged_vlans[j] != ifc->untagged_vlan; j++) {
            if (gifc[i].tagged_vlans[j] == NO_VLAN) {
              doSendFrame = false;
              break;
            }
          }

          if (doSendFrame) {
            const uint8_t *frame1 = frame;
            uint8_t frame2[frame_size + 4];

            fprintf(stderr, "dest address: ");
            printMac(&gifc[i].mac);
            fprintf(stderr, ", dest: %s\n", gifc[i].ifc_name);

            struct Q q = {0x0081, 0x0100};
            memcpy(&frame2, frame1, 12);
            memcpy(&frame2[12], &q, sizeof(struct Q));
            memcpy(&frame2[16], &frame1[12], frame_size - 12);

            struct EthernetHeader ethernetHeader1;
            memcpy(&ethernetHeader1, frame1, sizeof(ethernetHeader1));


            fprintf(stderr, "ethernetHeader.src:\n");
            printMac(&ethernetHeader1.src);
            fprintf(stderr, "ethernetHeader.dst:\n");
            printMac(&ethernetHeader1.dst);
            fprintf(stderr, "ethernetHeader.vlanId: %04X\n", ethernetHeader1.vlanId);
            fprintf(stderr, "ethernetHeader.vlanId: %04X\n", ethernetHeader1.tag);

            forward_to(&gifc[i], frame2, sizeof(frame2));
          }
        }
      }
    }
  }
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
 * Handle control message @a cmd.
 *
 * @param cmd text the user entered
 * @param cmd_len length of @a cmd
 */
static void
handle_control (char *cmd,
		size_t cmd_len)
{
  cmd[cmd_len - 1] = '\0';
  fprintf (stderr,
           "Received command `%s' (ignored)\n",
           cmd);
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

/**
 * Parse tagged interface specification found between @a start
 * and @a end.
 *
 * @param start beginning of tagged specification, with ':'
 * @param end end of tagged specification, should point to ']'
 * @param off interface offset for error reporting
 * @param ifc[out] what to initialize
 * @return 0 on success
 */
static int
parse_tagged (const char *start,
	      const char *end,
	      int off,
	      struct Interface *ifc)
{
  char *spec;
  unsigned int pos;

  if (':' != *start)
  {
    fprintf (stderr,
	     "Tagged definition for interface #%d lacks ':'\n",
	     off);
    return 1;
  }
  start++;
  spec = strndup (start,
		  end - start);
  if (NULL == spec)
  {
    perror ("strndup");
    return 1;
  }
  pos = 0;
  for (const char *tok = strtok (spec,
				 ",");
       NULL != tok;
       tok = strtok (NULL,
		     ","))
  {
    unsigned int tag;

    if (pos == MAX_VLANS)
    {
      fprintf (stderr,
	       "Too many VLANs specified for interface #%d\n",
	       off);
      free (spec);
      return 1;
    }
    if (1 != sscanf (tok,
		     "%u",
		     &tag))
    {
      fprintf (stderr,
	       "Expected number in tagged definition for interface #%d\n",
	       off);
      free (spec);
      return 1;
    }
    if (tag > MAX_VLANS)
    {
      fprintf (stderr,
	       "%u is too large for a 802.1Q VLAN ID (on interface #%d)\n",
	       tag,
	       off);
      free (spec);
      return 1;
    }
    ifc->tagged_vlans[pos++] = (int16_t) tag;
  }
  ifc->tagged_vlans[pos] = NO_VLAN;
  free (spec);
  return 0;
}


/**
 * Parse untagged interface specification found between @a start
 * and @a end.
 *
 * @param start beginning of tagged specification, with ':'
 * @param end end of tagged specification, should point to ']'
 * @param off interface offset for error reporting
 * @param ifc[out] what to initialize
 * @return 0 on success
 */
static int
parse_untagged (const char *start,
		const char *end,
		int off,
		struct Interface *ifc)
{
  char *spec;
  unsigned int tag;

  if (':' != *start)
  {
    fprintf (stderr,
	     "Untagged definition for interface #%d lacks ':'\n",
	     off);
    return 1;
  }
  start++;
  spec = strndup (start,
		  end - start);
  if (NULL == spec)
  {
    perror ("strndup");
    return 1;
  }
  if (1 != sscanf (spec,
		   "%u",
		   &tag))
  {
    fprintf (stderr,
	     "Expected number in untagged definition for interface #%d\n",
	     off);
    free (spec);
    return 1;
  }
  if (tag > MAX_VLANS)
  {
    fprintf (stderr,
	     "%u is too large for a 802.1Q VLAN ID (on interface #%d)\n",
	     tag,
	     off);
    free (spec);
    return 1;
  }
  ifc->untagged_vlan = (int16_t) tag;
  free (spec);
  return 0;
}


/**
 * Parse command-line argument with interface specification.
 *
 * @param arg command-line argument
 * @param off offset of @a arg for error reporting
 * @param ifc interface to initialize (ifc_name, tagged_vlans and untagged_vlan).
 * @return 0 on success
 */
static int
parse_vlan_args (const char *arg,
		 int off,
		 struct Interface *ifc)
{
  const char *openbracket;
  const char *closebracket;

  ifc->tagged_vlans[0] = NO_VLAN;
  ifc->untagged_vlan = NO_VLAN;
  openbracket = strchr (arg,
			(unsigned char) '[');
  if (NULL == openbracket)
  {
    ifc->ifc_name = strdup (arg);
    if (NULL == ifc->ifc_name)
    {
      perror ("strdup");
      return 1;
    }
    ifc->untagged_vlan = DEFAULT_VLAN;
    return 0;
  }
  ifc->ifc_name = strndup (arg,
			   openbracket - arg);
  if (NULL == ifc->ifc_name)
  {
    perror ("strndup");
    return 1;
  }
  openbracket++;
  closebracket = strchr (openbracket,
			 (unsigned char) ']');
  if (NULL == closebracket)
  {
    fprintf (stderr,
	     "Interface definition #%d includes '[' but lacks ']'\n",
	     off);
    return 1;
  }
  switch (*openbracket)
  {
  case 'T':
    return parse_tagged (openbracket + 1,
			 closebracket,
			 off,
			 ifc);
    break;
  case 'U':
    return parse_untagged (openbracket + 1,
			   closebracket,
			   off,
			   ifc);
    break;
  default:
    fprintf (stderr,
	     "Unsupported tagged/untagged specification `%c' in interface definition #%d\n",
	     *openbracket,
	     off);
    return 1;
  }
}


#include "loop.c"


/**
 * Launches the vswitch.
 *
 * @param argc number of arguments in @a argv
 * @param argv binary name, followed by list of interfaces to switch between
 * @return not really
 */
int
main (int argc,
      char **argv)
{
  struct Interface ifc[argc-1];

  (void) print;
  memset (ifc,
	  0,
	  sizeof (ifc));
  num_ifc = argc - 1;
  gifc = ifc;
  for (unsigned int i=1;i<argc;i++)
  {
    ifc[i-1].ifc_num = i;
    if (0 != parse_vlan_args (argv[i], i, &ifc[i-1])){
      return 1;
    }
  }
  loop ();
  return 0;
}
