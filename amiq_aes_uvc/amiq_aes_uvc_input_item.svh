////////////////////////////////////////////////////////////////////////////////
// Company:       AMIQ CONSULTING
// Engineer:      Andrei Neleptcu
//
// Description:   AES-UVC - UVC Input Item
////////////////////////////////////////////////////////////////////////////////
`ifndef __AMIQ_AES_UVC_INPUT_ITEM
`define __AMIQ_AES_UVC_INPUT_ITEM

/*
 * Class: amiq_aes_uvc_input_item
 *
 * Description: Input item for the UVC containing all components required for an AES transaction
 */
class amiq_aes_uvc_input_item extends uvm_sequence_item;

  /*
   * Variable: key
   *
   * Description: Secret key used to set up the AES transaction
   */
  rand byte unsigned key [`AES_UVC_MAX_KEY_BYTE_LENGTH];

  /*
   * Variable: data
   *
   * Description: Data to be encrypted/decrypted in the AES transaction
   */
  rand byte unsigned data [];

  /*
   * Variable: iv
   *
   * Description: Initialization vector used to set up the AES transaction
   */
  rand byte unsigned iv [`AES_UVC_IV_BYTE_LENGTH];

  /*
   * Variable: transaction_setup
   *
   * Description: Packed structure containing the setup information for the AES transaction
   */
  rand amiq_aes_setup transaction_setup;

  // Factory registering the fields
  `uvm_object_utils_begin(amiq_aes_uvc_input_item)
    `uvm_field_sarray_int(key,               UVM_ALL_ON)
    `uvm_field_sarray_int(data,              UVM_ALL_ON)
    `uvm_field_sarray_int(iv,                UVM_ALL_ON)
    `uvm_field_object    (transaction_setup, UVM_ALL_ON)
  `uvm_object_utils_end

  // Constraining the item to have a valid key size
  constraint transaction_setup_c {
    transaction_setup.key_size != amiq_aes_uvc_pkg::AES_INVALID;
    data.size() == 16;
    //soft transaction_setup.key_size != amiq_aes_uvc_pkg::AES_INVALID;

    //Constraint added for ease of simulation time!
    //soft (transaction_setup.block_mode != AES_CFB1) && (transaction_setup.block_mode != AES_CFB8);
  }

  function new(string name = "amiq_aes_uvc_input_item");
    super.new(name);
    transaction_setup = amiq_aes_setup::type_id::create("transaction_setup");
  endfunction

  // Converts the information in an input item to a string format
  virtual function string convert2string();
    byte unsigned key_chars_unused = 16 * (4 - (transaction_setup.key_size + 1));

    string message = { "=====================\n",
      (transaction_setup.new_setup == AES_TRUE) ? "NEW Setup, Type:" : "OLD Setup, IGNORE-> Type:",
      transaction_setup.transaction_type.name(),
      ", Key:", transaction_setup.key_size.name(),
      ", Mode:", transaction_setup.block_mode.name(),
      $sformatf("\nKEY:  %0h", `AES_UVC_MAX_KEY_BIT_LENGTH'({ >> {key}}))};
    message = {message.substr(0, message.len() - int'(key_chars_unused) - 1),
      $sformatf("\nDATA: %0h", `AES_UVC_DATA_BIT_LENGTH'({ >> {data}})),
      $sformatf("\nIV:   %0h", `AES_UVC_IV_BIT_LENGTH'({ >> {iv}})),
      "\n=====================\n"};

    return message;
  endfunction

  // Print function for Input Item
  virtual function void print();
    `uvm_info(this.get_full_name(), this.convert2string(), UVM_LOW)
  endfunction

endclass

`endif // __AMIQ_AES_UVC_INPUT_ITEM

