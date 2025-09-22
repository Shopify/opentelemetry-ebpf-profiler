// This file contains definitions for the ruby tracer to be shared with golang

#define ADDR_MASK_48_BIT  0x0000FFFFFFFFFFFFULL  // Lower 48 bits for address
#define EXTRA_TYPE_MASK   0x00FF000000000000ULL  // Bits 48-55 for uint8

typedef enum Extra_Addr_Types {
  ADDR_TYPE_NONE,
  ADDR_TYPE_CFP,
  ADDR_TYPE_CME,
  ADDR_TYPE_EP,
} Extra_Addr_Type;
