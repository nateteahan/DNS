#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#define BUF_SIZE 500

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

typedef struct
{
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
} dns_rr;

struct dns_answer_entry;
struct dns_answer_entry
{
	char *value;
	struct dns_answer_entry *next;
};
typedef struct dns_answer_entry dns_answer_entry;

void free_answer_entries(dns_answer_entry *ans)
{
	dns_answer_entry *next;
	while (ans != NULL)
	{
		next = ans->next;
		free(ans->value);
		free(ans);
		ans = next;
	}
}

void print_bytes(unsigned char *bytes, int byteslen)
{
	int i, j, byteslen_adjusted;
	unsigned char c;

	if (byteslen % 8)
	{
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	}
	else
	{
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++)
	{
		if (!(i % 8))
		{
			if (i > 0)
			{
				for (j = i - 8; j < i; j++)
				{
					if (j >= byteslen_adjusted)
					{
						printf("  ");
					}
					else if (j >= byteslen)
					{
						printf("  ");
					}
					else if (bytes[j] >= '!' && bytes[j] <= '~')
					{
						printf(" %c", bytes[j]);
					}
					else
					{
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted)
			{
				printf("\n%02X: ", i);
			}
		}
		else if (!(i % 4))
		{
			printf(" ");
		}
		if (i >= byteslen_adjusted)
		{
			continue;
		}
		else if (i >= byteslen)
		{
			printf("   ");
		}
		else
		{
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

void canonicalize_name(char *name)
{
	/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */

	int namelen, i;

	// leave the root zone alone
	if (strcmp(name, ".") == 0)
	{
		return;
	}

	namelen = strlen(name);
	// remove the trailing dot, if any
	if (name[namelen - 1] == '.')
	{
		name[namelen - 1] = '\0';
	}

	// make all upper-case letters lower case
	for (i = 0; i < namelen; i++)
	{
		if (name[i] >= 'A' && name[i] <= 'Z')
		{
			name[i] += 32;
		}
	}
}

int name_ascii_to_wire(char *name, unsigned char *wire)
{
	/* 
	 * Convert a DNS name from string representation (dot-separated labels)
	 * to DNS wire format, using the provided byte array (wire).  Return
	 * the number of bytes used by the name in wire format.
	 *
	 * INPUT:  name: the string containing the domain name
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *              wire-formatted name should be constructed
	 * OUTPUT: the length of the wire-formatted name.
	 */
	int wire_index = 0;
	int length;
	char *token = strtok(name, ".");

	while (token != NULL)
	{
		length = strlen(token);
		wire[wire_index] = (char)length;
		//Store the size of the string first, increment index by one
		wire_index++;

		//Store the token in the wire, increment the index by its length
		strncpy(&wire[wire_index], token, length);

		// Grab the next token
		token = strtok(NULL, ".");
		wire_index += length;
	}
	wire[wire_index++] = 0x00;
	return wire_index;
}

char *name_ascii_from_wire(unsigned char *wire, int *indexp)
{
	/* 
	 * Extract the wire-formatted DNS name at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return its string
	 * representation (dot-separated labels) in a char array allocated for
	 * that purpose.  Update the value pointed to by indexp to the next
	 * value beyond the name.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp, a pointer to the index in the wire where the
	 *              wire-formatted name begins
	 * OUTPUT: a string containing the string representation of the name,
	 *              allocated on the heap.
	 */
}
void create_linked_list(unsigned char *wire, dns_answer_entry *previous, int num_records, int *index)
{
	/* This is where the linked list will be created.
		Since head is passed by reference, you only need to iterate num_records amount of times
		and ignore a return value. */

	// i will serve to keep track of which answer we are on
	// index to keep track of the byte index
	for (int i = 0; i < num_records; i++)
	{
		// Create a new struct with each iteration
		dns_rr *curr_rr = (dns_rr *)malloc(sizeof(dns_rr));
		curr_rr->name = NULL;
		*index += 2;
		curr_rr->type = (wire[*index] << 8) | wire[*index + 1];
		*index += 2;
		curr_rr->class = (wire[*index] << 8) | wire[*index + 1];
		*index += 2;
		curr_rr->ttl = (wire[*index] << 24) | (wire[*index + 1] << 16) | (wire[*index + 2] << 8) | wire[*index + 3];
		*index += 4;
		curr_rr->rdata_len = wire[*index] << 8 | wire[*index + 1];
		*index += 2;
		curr_rr->rdata = malloc(sizeof(unsigned char) * curr_rr->rdata_len);
		sprintf(curr_rr->rdata, "%d.%d.%d.%d", wire[*index], wire[*index + 1], wire[*index + 2], wire[*index + 3]);
		*index += 4;

		/* Create head of linked list */
		dns_answer_entry *next = NULL;
		next = (dns_answer_entry *)malloc(sizeof(dns_answer_entry));

		next->value = curr_rr->rdata;
		next->next = NULL;

		if (i < num_records - 1) {
			previous->next = next;
			previous = next;
		}
	}
}

dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only)
{
	/* 
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a 
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the
	 *              wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are extracting a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */
	/* EXTRACT INFO FROM BYTES */
	/* CREATE DNS_RR STRUCT */
	dns_rr *current_rr = (dns_rr *)malloc(sizeof(dns_rr));
	current_rr->name = NULL;
	*indexp += 2;
	current_rr->type = (wire[*indexp] << 8) | wire[*indexp + 1];
	*indexp += 2;
	current_rr->class = (wire[*indexp] << 8) | wire[*indexp + 1];
	*indexp += 2;
	current_rr->ttl = (wire[*indexp] << 24) | (wire[*indexp + 1] << 16) | (wire[*indexp + 2] << 8) | wire[*indexp + 3];
	*indexp += 4;
	current_rr->rdata_len = wire[*indexp] << 8 | wire[*indexp + 1];
	*indexp += 2;

	current_rr->rdata = malloc(sizeof(unsigned char) * current_rr->rdata_len); //Make sure this works
	sprintf(current_rr->rdata, "%d.%d.%d.%d", wire[*indexp], wire[*indexp + 1], wire[*indexp + 2], wire[*indexp + 3]);
	*indexp += 4;

	// printf("%s\n", current_rr->rdata);
	return *current_rr;
}

int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only)
{
	/* 
	 * Convert a DNS resource record struct to DNS wire format, using the
	 * provided byte array (wire).  Return the number of bytes used by the
	 * name in wire format.
	 *
	 * INPUT:  rr: the dns_rr struct containing the rr record
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *             wire-formatted resource record should be constructed
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are constructing a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the length of the wire-formatted resource record.
	 *
	 */
}

unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire)
{
	/* 
	 * Create a wire-formatted DNS (query) message using the provided byte
	 * array (wire).  Create the header and question sections, including
	 * the qname and qtype.
	 *
	 * INPUT:  qname: the string containing the name to be queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes where the DNS wire
	 *               message should be constructed
	 * OUTPUT: the length of the DNS wire message
	 */
	int length = name_ascii_to_wire(qname, wire);
	// print_bytes(wire, strlen(wire));
	return length;
}

dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire)
{
	/* 
	 * Extract the IPv4 address from the answer section, following any
	 * aliases that might be found, and return the string representation of
	 * the IP address.  If no address is found, then return NULL.
	 *
	 * INPUT:  qname: the string containing the name that was queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
	 * OUTPUT: a linked list of dns_answer_entrys the value member of each
	 * reflecting either the name or IP address.  If
	 */
}

int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, char *port)
{
	/* 
	 * Send a message (request) over UDP to a server (server) and port
	 * (port) and wait for a response, which is placed in another byte
	 * array (response).  Create a socket, "connect()" it to the
	 * appropriate destination, and then use send() and recv();
	 *
	 * INPUT:  request: a pointer to an array of bytes that should be sent
	 * INPUT:  requestlen: the length of request, in bytes.
	 * INPUT:  response: a pointer to an array of bytes in which the
	 *             response should be received
	 * OUTPUT: the size (bytes) of the response received
	 */

	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s, j;
	size_t len;
	ssize_t nread;
	char buf[BUF_SIZE];

	// print_bytes(request, requestlen);
	/* Obtain address(es) matching host/port */

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;		/* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0; /* Any protocol */

	s = getaddrinfo(server, port, &hints, &result);
	if (s != 0)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}
	// fprintf(stderr, "Request length: %d\n\n", requestlen);
	/* getaddrinfo() returns a list of address structures.
	   Try each address until we successfully connect(2).
	   If socket(2) (or connect(2)) fails, we (close the socket
	   and) try the next address. */

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		sfd = socket(rp->ai_family, rp->ai_socktype,
					 rp->ai_protocol);
		if (sfd == -1)
			continue;

		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break; /* Success */

		close(sfd);
	}

	if (rp == NULL)
	{ /* No address succeeded */
		fprintf(stderr, "Could not connect\n");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(result); /* No longer needed */

	/* Send remaining command-line arguments as separate
	   datagrams, and read responses from server */
	/* +1 for terminating null byte */

	if (requestlen + 1 > BUF_SIZE)
	{
		fprintf(stderr,
				"Ignoring long message in argument %d\n", j);
	}

	if (write(sfd, request, requestlen) != requestlen)
	{
		fprintf(stderr, "partial/failed write\n");
		exit(EXIT_FAILURE);
	}
	// printf("Sent %d bytes to server\n", requestlen);

	nread = read(sfd, response, BUF_SIZE);
	if (nread == -1)
	{
		perror("read");
		exit(EXIT_FAILURE);
	}

	// printf("Received %zd bytes: %s\n", nread, response);
	return nread;
}

dns_answer_entry *resolve(char *qname, char *server, char *port)
{
	// fprintf(stderr, "%s\n %s\n %s\n", qname, server, port);
	unsigned char dns_message[1024];
	//Hard code in the first 12 bytes.
	int index = 0;
	dns_message[index++] = rand();
	dns_message[index++] = rand();
	dns_message[index++] = 0x01;
	dns_message[index++] = 0x00;
	dns_message[index++] = 0x00;
	dns_message[index++] = 0x01;
	dns_message[index++] = 0x00;
	dns_message[index++] = 0x00;
	dns_message[index++] = 0x00;
	dns_message[index++] = 0x00;
	dns_message[index++] = 0x00;
	dns_message[index++] = 0x00;
	index += create_dns_query(qname, '1', &dns_message[12]);
	dns_message[index++] = 0x00;
	dns_message[index++] = 0x01;
	dns_message[index++] = 0x00;
	dns_message[index++] = 0x01;

	// printf("Query message:");
	// print_bytes(dns_message, index);

	unsigned char response[1024];
	int response_size = send_recv_message(dns_message, index, response, server, port);

	// Get the number of records from the response
	char str[2];
	memcpy(str, &response[6], 2);
	int num_records = str[0] << 8 | str[1];
	dns_rr first_dns = rr_from_wire(response, &index, 0);

		/* Create head of linked list */
	dns_answer_entry *head = NULL;
	if (first_dns.type == 1) {
		head = (dns_answer_entry *)malloc(sizeof(dns_answer_entry));
		head->value = first_dns.rdata;
		head->next = NULL;
		if (num_records > 1) {
			create_linked_list(response, head, num_records, &index);
		}
	}
	return head;
}

int main(int argc, char *argv[])
{
	char *port;
	dns_answer_entry *ans_list, *ans;
	if (argc < 3)
	{
		fprintf(stderr, "Usage: %s <domain name> <server> [ <port> ]\n", argv[0]);
		exit(1);
	}
	if (argc > 3)
	{
		port = argv[3];
	}
	else
	{
		port = "53";
	}
	ans = ans_list = resolve(argv[1], argv[2], port);
	while (ans != NULL)
	{
		printf("%s\n", ans->value);
		ans = ans->next;
	}
	if (ans_list != NULL)
	{
		free_answer_entries(ans_list);
	}
}
