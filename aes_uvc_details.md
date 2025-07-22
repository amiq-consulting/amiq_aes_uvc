# AES UVC - Detailed Documentation

The AES UVC introduces multiple custom data types and defines, as well as public methods to access the AES functionalities.

The following paragraphs will elaborate on the main functionalities. Further information may be found throughout the code's comments.

## Utils Library - `amiq_aes_uvc_utils_lib`
All the defines and data types used throughout the UVC's implementation are elaborated in the Utils Library as follows:

### Defines
-   `AES_UVC_MAX_KEY_BYTE_LENGTH` – **32** (maximum width of the secret key in bytes)
-   `AES_UVC_MIN_KEY_BYTE_LENGTH` – **16** (minimum width of the secret key in bytes)
-   `AES_UVC_MAX_KEY_BIT_LENGTH` – **256** (maximum width of the secret key in bits)
-   `AES_UVC_IV_BYTE_LENGTH` – **16** (width of the initialization vector in bytes)
-   `AES_UVC_IV_BIT_LENGTH` – **128** (width of the initialization vector in bits)
-   `AES_UVC_DATA_BYTE_LENGTH` – **16** (width of the data block in bytes)
-   `AES_UVC_DATA_BIT_LENGTH` – **128** (width of the data block in bits)
-   `AES_UVC_BYTE` – **8** (general byte value define)
-   `AES_UVC_PAD_BYTE` – **8’b10000000** (padding byte recommended by NIST)
-   `AES_BELOW_THRESHOLD_BIN` – **0** (bin value for counting nof transactions below set threshold)
-   `AES_ABOVE_THRESHOLD_BIN` – **1** (bin value for counting nof transactions above set threshold)
-   `AES_SAME_SETUP_BIN` – **2** (bin value for counting nof transactions which had the same new setup)
-   `AES_SAME_KEY_IV_BIN` – **3** (bin value for counting nof transactions which had the same key/iv pair)
-   `AES_INFO` – **2’d2** (invalid key/iv transactions message type)
-   `AES_WARNING` – **2’d1** (invalid key/iv transactions message type)
-   `AES_ERROR` – **2’d0** (invalid key/iv transactions message type)
-   `AES_MAX_BYTE_VALUE` – **255** (maximum value of a byte)

### Data types
-   `amiq_aes_bool_e` – **AES_TRUE / AES_FALSE** (used for transaction setup).
-   `amiq_aes_encrypt_decrypt_e` – **AES_ENCRYPTION / AES_DECRYPTION** (used for transaction setup).
-   `amiq_aes_key_size_e` – **AES_INVALID / AES_128 / AES_129 / AES_256** (used for transaction setup).
-   `amiq_aes_block_mode_e` – **AES_ECB / AES_CTR / AES_CBC / AES_OFB / AES_CFB1 / AES_CFB8 / AES_CFB128** (used for transaction setup).
-   `amiq_aes_setup` – class containing randomizable **amiq_aes_bool_e, amiq_aes_encrypt_decrypt_e, amiq_aes_key_size_e, amiq_aes_block_mode_e** fields.
-   `amiq_packed_128bit_t` – typedef for bit[127:0]
-   `amiq_packed_256bit_t` – typedef for bit[255:0]  
-   `amiq_setup_occurence` – class containing:
-   `transaction_setup` – class of type `amiq_aes_setup`
    -   `key(256bits)` – of type `amiq_packed_256bit_t`
    -   `iv(128bits)` – of type `amiq_packed_128bit_t`
    -   `sim_time(64bits)` – of type time
-   `amiq_setup_occurence_q_t` – typedef required for returning a queue of `amiq_setup_occurence` from a function
-   `amiq_time_q_t` – typedef required for returning a queue of `time` from a function
## Input Item - `amiq_aes_uvc_input_item`
Specialized item containing randomizable fields used in AES transactions and a custom print function:
-   **key** – a 32 byte unpacked array containing the Secret Key used for the setup of an AES session.
-   **data** – a dynamic size byte unpacked array containing the plaintext for the algorithm.
-   **iv**  – a 16 byte unpacked array containing the initialization vector used for the setup of an AES block-mode session.
-   **transaction_setup** – a class of type `amiq_aes_setup` containing:
    -   **new_setup** (1bit) – An enum of type `amiq_aes_bool` with the values:
        -   **AES_TRUE** – a new session will be set up, all item fields will be interpreted.
        -   **AES_FALSE** – using the current session, all fields besides data will be ignored.
    -   **transaction_type** (1bit) – An enum of type `amiq_aes_encrypt_decrypt` with the values:
        -   **AES_ENCRYPTION** – signaling an encryption session.
        -   **AES_DECRYPTION** – signaling a decryption session.
    -   **key_size** (2bits) – An enum of type `amiq_aes_key_size` with the values:
        -   **INVALID** – invalid key size.
        -   **AES_128** – key size is 128 bits.
        -   **AES_192** – key size is 192 bits.
        -   **AES_256** – key size is 256 bits.
    -   **block_mode** (3bits) – An enum of type `amiq_aes_block_mode` with the values:
        -   **AES_ECB** – the block mode used will be ECB.
        -   **AES_CTR** – the block mode used will be CTR.
        -   **AES_CBC** – the block mode used will be CBC.
        -   **AES_OFB** – the block mode used will be OFB.
        -   **AES_CFB1** – the block mode used will be CFB with 1 bit offset.
        -   **AES_CFB8** - the block mode used will be CFB with 8 bits offset.
        -   **AES_CFB128** - the block mode used will be CFB with 128 bits offset.
 
## Output Item - `amiq_aes_uvc_output_item`
Specialized item containing the output data and a custom print function:
 - **data** – a dynamic size byte unpacked array containing the result of the AES operations.
 
## Communication Component (UVC) - `amiq_aes_uvc`
The communication component also has public coverage query functions:
- `get_number_of_transactions_without_key_change()` – Returns an `int unsigned` number of transactions using the same key.
- `get_same_key_iv_occurence_stats()` – Returns a queue of type `amiq_setup_occurence_q_t` which stores information about the key, iv and simulation time when the same key/iv pair were used.
- `get_same_new_setup_occurence_stats()` – Returns an `amiq_time_q_t` queue storing information about the time when new setups with the same setup fields occurred.

## Core `amiq_aes_uvc_core`
The core performs the AES functionalities through multiple publicly accesible methods:
-   `reset_setup()` – This function resets the internal `valid_key` and `valid_IV` flags that signal a key/iv were set using the set_key() and set_iv() functions  
-   `set_key(byte unsigned new_key[], amiq_aes_key_size size)` – This function sets the key for a session. If a valid key (128/192/256 bit) is not set, the user will be informed with a ``` `uvm_info```.  
-   `set_iv(byte unsigned new_iv[])` – This function sets the IV for a session that uses a block mode different form ECB (they require the IV). If a valid IV (128 bit) is not set, the user will be informed with a ``` `uvm_info```.
    
If an invalid key and/or IV are set, all the following encryption/decryption methods will prompt the user with a uvm_info/warning/error regarding the situation and will not modify the output_data[] parameter. The user may choose between info/warning/error from the config object.
-   `xcrypt_ecb(input byte unsigned state[], input int unsigned state_size, input amiq_aes_encrypt_decrypt operation, output byte unsigned output_data[], input byte unsigned missing_bits_in_last_byte = 0) `– X-Crypt wrapper for ECB mode which calls `encrypt_ecb()` or `decrypt_ecb()` based on operation.  
    -   `encrypt_ecb(input byte unsigned state[], input int unsigned state_size, output byte unsigned output_data[], input byte unsigned missing_bits_in_last_byte = 0)` – This function checks if a valid key was set and starts the Cipher function (the ECB mode encryption) creating the output_data corresponding to the state.  
    -   `decrypt_ecb(input byte unsigned state[], input int unsigned state_size, output byte unsigned output_data[], input byte unsigned missing_bits_in_last_byte = 0)` – This function checks if a valid key was set and starts the Inv_Cipher function (the ECB mode decryption) creating the output_data corresponding to the state.  

-   `xcrypt_ctr(input byte unsigned state[], input int unsigned state_size, input amiq_aes_encrypt_decrypt operation, output byte unsigned output_data[], input byte unsigned missing_bits_in_last_byte = 0)` – This function checks if a valid key and a valid iv were set and starts the Cipher function (the ECB mode encryption) with the iv as input, XOR-ing the result with the state, creating the output_data corresponding to the state.  

-   `xcrypt_cbc(input byte unsigned state[], input int unsigned state_size, input amiq_aes_encrypt_decrypt operation, output byte unsigned output_data[], input byte unsigned missing_bits_in_last_byte = 0)` – X-Crypt wrapper for CBC mode which calls encrypt_cbc() or decrypt_cbc() based on operation.  
    -   `encrypt_cbc(input byte unsigned state[], input int unsigned state_size, output byte unsigned output_data[], input byte unsigned missing_bits_in_last_byte = 0)` – This function checks if a valid key and a valid iv were set, XOR-ing the state with the iv, then feeding the result to the Cipher function (the ECB mode encryption) with the state as input, storing the output as the new iv for the next operation, creating the output_data corresponding to the state.  
    -   `decrypt_cbc(input byte unsigned state[], input int unsigned state_size, output byte unsigned output_data[], input byte unsigned missing_bits_in_last_byte = 0)` – This function checks if a valid key and a valid iv were set and starts the Inv_Cipher function (the ECB mode encryption) with the state as input, XOR-ing the result with the iv and initializing the next iv with the state before being modified by Inv_Cipher, creating the output_data corresponding to the state.  

-   `xcrypt_ofb(input byte unsigned state[], input int unsigned state_size, input amiq_aes_encrypt_decrypt operation, output byte unsigned output_data[], input byte unsigned missing_bits_in_last_byte = 0)` – This function checks if a valid key and a valid iv were set and starts the Cipher function (the ECB mode encryption) with the iv as input, XOR-ing the result with the state, initializing the next iv with the encrypted iv, creating the output_data corresponding to the state. 
-   `xcrypt_cfb(input byte unsigned state[], input int unsigned state_size, input amiq_aes_encrypt_decrypt operation, input amiq_aes_block_mode cfb_type, output byte unsigned output_data[], input byte unsigned missing_bits_in_last_byte = 0)` – This function checks if a valid key and a valid iv were set and starts the Cipher function (the ECB mode encryption) with the iv as input, concatenating different bit offsets of the result with the input block (depending on the CFB mode chosen). This function may be used as is provided or through the individual utility functions, each choosing the appropriate parameters to call the `xcrypt_cfb` function:
-   `encrypt_cfb1`, `decrypt_cfb1`
-   `encrypt_cfb8`, `decrypt_cfb8`
-   `encrypt_cfb128`, `decrypt_cfb128`

all of them having the parameter list `(input byte unsigned state[], input int unsigned state_size, output byte unsigned output_data[], input byte unsigned missing_bits_in_last_byte = 0) `. 
-   `aes_main(input byte unsigned state[], input int unsigned state_size, input amiq_aes_encrypt_decrypt operation, input amiq_aes_block_mode block_mode, output byte unsigned output_data[], input byte unsigned missing_bits_in_last_byte = 0)` – This function uses the parameters to decide automatically what individual AES method to call. 

All AES encryption/decryption functions can perform operations on non-standard 128bit inputs applying the general padding of a bit of 1, completing to the nearest multiple of 128bits with zeros. The space for the output_data is allocated inside the functions and will be a multiple of 128 bits, except for CTR mode which does not require padding.

## Coverage Collector - `amiq_aes_uvc_coverage_collector`
This component implements the coverage collection for the UVC’s transactions. The coverage data is collected inside the Core component, packed as an `amiq_aes_uvc_input_item` and sent to the coverage collector through the Core’s `aes_input_item_ap` analysis port.
    
The following coverage is being collected:
-   `key_bytes_cg` – Sampling pairs of bytes and their corresponding index from the key array:
    -   **key_bytes_cp** – Bins of 0, 255 and powers of 2 between 0 and 255 for each byte of the key.
    -   **index_cp** – All values ranging from 0 to 31(max index).
    -   **key_value_cross** – All combinations of byte / index (observing that each byte had all values).
-   `iv_bytes_cg` – Sampling pairs of bytes and their corresponding index from the IV array:
    -   **iv_bytes_cp** – Bins of 0, 255 and powers of 2 between 0 and 255 for each byte of the IV.
    -   **index_cp** – All values ranging from 0 to 16(max index).
    -   **key_value_cross** – All combinations of byte / index (observing that each byte had all values.
-   `data_bytes_cg` – Sampling pairs of bytes and their corresponding index from the data array:
    -   **data_bytes_cp** – Bins of 0, 255 and powers of 2 between 0 and 255 for each byte of the data.
    -   **index_cp** – All values ranging from 0 to 16(max index).
    -   **key_value_cross** – All combinations of byte / index (observing that each byte had all values).
-   `setup_information_cg` – Covergroup sampling the values for the `amiq_aes_setup` field.
    -   **key_size_cp** – Bins for AES_128, AES_192, AES_256.
    -   **key_size_transitions_cp** – All 3 sequence transitions among the key sizes (3^3 = 27 possible transitions).
    -   **block_mode_cp** – Bins for AES_ECB, AES_CTR, AES_CBC, AES_OFB, AES_CFB1, AES_CFB8, AES_CFB128.
    -   **block_mode_transitions_cp** – All 2 sequence transitions among the block modes (7^2 = 49 possible transitions).
    -   **transaction_type_cp** – Bins for AES_ENCRYPTION, AES_DECRYPTION.
    -   **transaction_cross** – All variations from key_size_cp, block_mode_cp and transaction_type_cp.
-   `statistics_cg` – Covergroup sampling the statistics from successive transactions.
    -   **nof_transactions_same_key_cp** – bins that have the define values AMIQ_AES_BELOW_THRESHOLD_BIN, AMIQ_AES_ABOVE_THRESHOLD_BIN. The number of hits will yield the number of transactions below and above the config object’s max_same_key_transactions field.
    -   **same_new_setup_cp** – A single bin of the define value AES_SAME_SETUP_BIN. The number of hits will yield the number of transactions in which the same setup (transaction type, block mode and key size) were used if the new_setup field of the transaction_setup was 1.
    -   **nof_transactions_same_iv_key_pair_cp** – A single bin of the define value AES_SAME_KEY_IV_BIN. The number of hits will yield the number of transactions in which a previous KEY and IV combination was reused (possible security risks as proposed by NIST).

The statistics_cg may be interrogated both through the UVC and the Coverage Collector components using the functions mentioned in the UVC.
## Config Object - `amiq_aes_uvc_config_obj`
This component stores flags regarding the coverage collector as follows:
-   **has_coverage** – `bit` – Enables the coverage if set to 1 and disables it if set to 0. This parameter guards the creation and connection of the coverage collector to the UVC.
-   **enable_stats_coverage** – `bit`– Enables the statistics_cg storage mechanisms if set to 1 and disables them if set to 0. Disabling the storage mechanisms affects the UVC coverage methods as they will return empty queues / hashmaps.
-   **toggle_setup_info_error** – `bit[1:0]` –Switches between uvm_info=2, uvm_warning=1 and uvm_error=0 as control mechanisms in the core component when checking for valid iv/key.
-   **verbosity_level** – `uvm_verbosity` – Sets the verbosity of the uvm_info from the control mechanisms.
-   **max_same_key_transactions** – `int unsigned` – Sets the maximum number of transactions allowed with the same key. The coverage collector will collect information about consecutive transactions using the same key only if the number of transactions is greater than max_same_key_transactions.

## Miscellaneous Library - `amiq_aes_uvc_misc_lib`
Contains custom array and item printing functions used for debugging:
-   `amiq_aes_print_hex_array_d(string ctx, byte unsigned array[], int length = byte_array.size())` – Builds and returns a string containing the ctx on the first line and segments of 16 bytes of the array in each subsequent line.
-   `amiq_aes_print_input_item_d(string ctx, amiq_aes_uvc_input_item item, bit timestamp = 0)` – Builds and returns a string containing the ctx and the time of the call on the first line (if timestamp = 1), and the convert2string() return value of the item on the subsequent lines.
-   `amiq_aes_print_output_item_d(string ctx, amiq_aes_uvc_output_item item, bit timestamp = 0)` – Builds and returns a string containing the ctx and the time of the call on the first line (if timestamp = 1), and the convert2string() return value of the item on the subsequent lines.

