////////////////////////////////////////////////////////////////////////////////
// Company:       AMIQ CONSULTING
// Engineer:      Andrei Neleptcu
//
// Description:   AES-UVC - UVC Utils
////////////////////////////////////////////////////////////////////////////////
`ifndef __AMIQ_AES_UVC_UTILS_LIB
`define __AMIQ_AES_UVC_UTILS_LIB

/* --------------------------
 * ---------DEFINES----------
 * --------------------------
 */

// Maximum key length in bytes
`define AES_UVC_MAX_KEY_BYTE_LENGTH 32

// Maximum key length in bytes
`define AES_UVC_MIN_KEY_BYTE_LENGTH 16

// Maximum key length in bITS
`define AES_UVC_MAX_KEY_BIT_LENGTH 256

// The IV length in bytes
`define AES_UVC_IV_BYTE_LENGTH 16

// The IV length in bits
`define AES_UVC_IV_BIT_LENGTH 128

// The Input / Output data length in bytes
`define AES_UVC_DATA_BYTE_LENGTH 16

// The Input / Output data length in bits
`define AES_UVC_DATA_BIT_LENGTH 128

// Number of bits in a byte
`define AES_UVC_BYTE 8

// Padding byte value
`define AES_UVC_PAD_BYTE 8'b10000000

// Coverage define: bin value for counting nof transactions below set threshold
`define AES_BELOW_THRESHOLD_BIN 0

// Coverage define: bin value for counting nof transactions above set threshold
`define AES_ABOVE_THRESHOLD_BIN 1

// Coverage define: bin value for counting nof transactions which had the same new setup
`define AES_SAME_SETUP_BIN 2

// Coverage define: bin value for counting nof transactions which had the same key/iv pair
`define AES_SAME_KEY_IV_BIN 3

// Define for invalid key/iv transactions message type
`define AES_INFO 2'd2

// Define for invalid key/iv transactions message type
`define AES_WARNING 2'd1

// Define for invalid key/iv transactions message type
`define AES_ERROR 2'd0

// Max value of a byte
`define AES_MAX_BYTE_VALUE 255

/* --------------------------
 * ---------TYPEDEFS---------
 * --------------------------
 */

// Bool enum
typedef enum bit {
  AES_TRUE  = 1, // True boolean value
  AES_FALSE = 0  // False boolean value
} amiq_aes_bool_e;

// Enum used to signal if a transaction is ENCRYPTION or DECRYPTION
typedef enum bit {
  AES_ENCRYPTION = 1, //The transaction will be an ENCRYPTION
  AES_DECRYPTION = 0  //The transaction will be a DECRYPTION
} amiq_aes_encrypt_decrypt_e;

// Enum used to set up the key width of the transaction
typedef enum bit [1 : 0] {
  AES_INVALID, //Signaling an invalid key size
  AES_128,     //Size of key is 128 bits
  AES_192,     //Size of key is 192 bits
  AES_256      //Size of key is 256 bits
} amiq_aes_key_size_e;

// Enum used to choose the block mode of the transaction
typedef enum bit [2 : 0] {
  AES_ECB,   // Electronic Codebook mode
  AES_CTR,   // Counter mode
  AES_CBC,   // Cipher chaining mode
  AES_OFB,   // Output feedback mode
  AES_CFB1,  // Cipher feedback mode with 1 bit offset
  AES_CFB8,  // Cipher feedback mode with 8 bit offset
  AES_CFB128 // Cipher feedback mode with 128 bit offset
} amiq_aes_block_mode_e;

// Packed struct defining a new setup for the core, a new setup will be interpreted only if the new_setup field is set
// to TRUE
class amiq_aes_setup extends uvm_object;
  rand amiq_aes_bool_e            new_setup; // Used to set up a new transaction or use the last setup transaction
  rand amiq_aes_encrypt_decrypt_e transaction_type; // The type of the transaction: ENCRYPTION/DECRYPTION
  rand amiq_aes_key_size_e        key_size;   // The size of the secret key
  rand amiq_aes_block_mode_e      block_mode; // The block mode used

  `uvm_object_utils_begin(amiq_aes_setup)
    `uvm_field_enum(amiq_aes_bool_e,            new_setup,        UVM_ALL_ON)
    `uvm_field_enum(amiq_aes_encrypt_decrypt_e, transaction_type, UVM_ALL_ON)
    `uvm_field_enum(amiq_aes_key_size_e,        key_size,         UVM_ALL_ON)
    `uvm_field_enum(amiq_aes_block_mode_e,      block_mode,       UVM_ALL_ON)
  `uvm_object_utils_end

  function new(string name = "amiq_aes_setup");
    super.new(name);
  endfunction

endclass;

typedef bit [127 : 0] amiq_packed_128bit_t; // Packed 128 bit value typedef

typedef bit [255 : 0] amiq_packed_256bit_t; // Packed 256 bit value typedef

// Setup occurence class
class amiq_setup_occurence extends uvm_object;
  amiq_aes_setup       transaction_setup; // Transaction setup
  amiq_packed_256bit_t key;               // Key
  amiq_packed_128bit_t iv;                // IV
  time                 sim_time;          // Sim tim

  `uvm_object_utils(amiq_setup_occurence)

  function new(string name = "amiq_setup_occurence");
    super.new(name);
    key      = '{default:0};
    iv       = '{default:0};
    sim_time = '{default:0};
  endfunction

endclass;

// Typedef required to return queues of type 'amiq_setup_occurence'
typedef amiq_setup_occurence amiq_setup_occurence_q_t[$];

// Typedef required to return queues of type 'time'
typedef time amiq_time_q_t[$];

`endif // __AMIQ_AES_UVC_UTILS_LIB
