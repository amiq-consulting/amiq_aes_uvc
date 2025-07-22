# AES UVC - A UVM Implementation

This repository provides a **Universal Verification Component (UVC)** for the **Advanced Encryption Standard (AES)**, implemented using the **Universal Verification Methodology (UVM)**. It includes support for multiple **NIST**-approved block cipher modes and is designed for use in verification environments at the transaction level.


## Supported features

- AES encryption and decryption with:
  - 128-bit, 192-bit, and 256-bit key lengths.
  - ECB, CBC, OFB, CTR, and CFB (1/8/128) block modes.
- Support for padding (as per [FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final))
- Communication through both TLM ports and public methods.

## The package

###  Utils Library - `amiq_aes_uvc_utils_lib`
Contains the defines, the custom enums used in the `transaction_setup` field of the Input Item and the data storage structures used in the Coverage Collector.

###  Miscellaneous Library - `amiq_aes_uvc_misc_lib`
Contains custom debugging functions to print hex arrays as segments of 16 bytes and Input/Output Items.

### Input and Output Items
The necessary data required for transactions is wrapped over Input and Output Items:
- **Input Item** - `amiq_aes_uvc_input_item`:
	- data : byte array
	- key : byte array
	- IV : byte array
	- **transaction setup** :
		- new_setup : signaling whether it is a new setup or not.
		- key_size : size of the AES secret key.
		- block_mode : one of the 5 block modes.
		- operation : encryption or decryption. 
- **Output Item** - `amiq_aes_uvc_output_item`:
	- data : byte array

###  Configuration Object - `amiq_aes_uvc_config_obj`
Manages parameters regarding the Coverage Collector such as: enabling coverage, enabling storage of statistics, defining the maximum number of transactions using the same key, as well as how key/IV guards inside the Core are handled (through uvm_info, uvm_warning or uvm_error).

###  Core - `amiq_aes_uvc_core`
Handles AES operations using three levels of abstraction:
- Level 1: AES individual `encryption/decryption` functions.
- Level 2: `xcrypt`functions wrapping over Level 1.
- Level 3: `aes_main` – wrapping over Level 2

Before calling any AES operation, a key and/or an IV should be set through the `set_key` and `set_iv` methods which check their validity.
The Core also collects data in order to send it to the Coverage Collector.

### Coverage Collector
Implements coverage metrics from the UVC verification plan:
- **Data-based coverage**: Each byte hits powers of 2 up to 255 ensuring full 8-bit toggling.
- **Configuration-based**: All combinations of key sizes, block modes, and operations.
- **Statistics-based**: Tracks repeated key/IV usage and configuration consistency.

### Communication Component
Provides a simple transaction system over the Core component
- Receives an `amiq_aes_uvc_input_item` through the implementation port.
- Performs AES transaction through the Core.
- Sends an `amiq_aes_uvc_output_item` through the analysis port.
- Optionally connects to the Coverage Collector.

## Validation
The UVC's output is validated through the annexes presented in [SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final). The Coverage Collector implements the coverage proposed in the vPlan, guaranteeing the UVC behaves appropriately in all possible configurations.

Through those two methods of validation, the UVC correctly handles any AES transaction, producing the desired output.
## Integration and Usage
The UVC was developed using UVM 1.1d and tested in multiple simulators such as Xcellium and Questa.

The `amiq_aes_uvc_pkg.sv` package may be imported inside the verification environment using:
`import amiq_aes_uvc_pkg::*;`

Afterwards, the UVC may be used in two ways:

### Instantiating the Communication Component
The UVC may be instantiated with:
```
amiq_aes_uvc my_aes_uvc;
my_aes_uvc = amiq_aes_uvc::type_id::create("my_aes_uvc", this);
```
An analysis port for sending items should be defined using:
```
uvm_analysis_port#(amiq_aes_uvc_input_item) my_aes_uvc_input_item_ap;
```
An implementation port for receiving items should be defined using:
```
`uvm_analysis_imp_decl(_aes_output_item)
uvm_analysis_imp_aes_output_item #(amiq_aes_uvc_output_item, amiq_aes_scoreboard) my_aes_uvc_output_item_imp;
```
The ports should be connected to the UVC's ports accordingly. In this scenario, the ports were defined inside the Scoreboard and the connection was made inside the Env's `connect_phase`:
```
scbd.my_aes_uvc_input_item_ap.connect(my_aes_uvc.aes_input_item_imp);
my_aes_uvc.aes_output_item_ap.connect(scbd.my_aes_uvc_output_item_imp);
```
An Input Item may be sent through the analysis port like:
```
my_aes_uvc_input_item_ap.write(my_input_item);
```
The Output Item will be received in the appropriately defined _write() function such as:
```
function void write_aes_output_item(amiq_aes_uvc_output_item my_output_item);
endfunction
```

### Instantiating the Core
The UVC may be used directly through the Core component by instantiating it:
```
amiq_aes_uvc_core my_aes_core;
my_aes_core = amiq_aes_uvc_core::type_id::create("my_aes_core", this);
```
The user may then choose the appropriate data necessary for input, receiving it in the `output_data` parameter.
Such a transaction may look like:
```
my_aes_core.set_key(key_byte_array);
my_aes_core.set_iv(key_iv_array);
my_aes_core.aes_main(data_byte_array, 16, AES_ENCRYPTION, AES_CTR, output_data, 7);
```
More information about the parameters of the public methods may be found in the `amiq_aes_core.svh` file.

## More information
The UVC and the behaviour of its components may be explored in ["AES UVC implementation in UVM" - AMIQ Consulting Blog](placeholder_link).
A more detailed documentation regarding the data types and functions inside the UVC may be found in the [detailed documentation](/aes_uvc_details.md)

The UVC was developed according to the [FIPS 197 - Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final) ,  alongside [SP 800-38A - Recommendation for Block Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final).


