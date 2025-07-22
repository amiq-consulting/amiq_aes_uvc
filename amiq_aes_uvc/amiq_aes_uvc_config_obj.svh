////////////////////////////////////////////////////////////////////////////////
// Company:       AMIQ CONSULTING
// Engineer:      Andrei Neleptcu
//
// Description:   AES-UVC - UVC Config Object
////////////////////////////////////////////////////////////////////////////////
`ifndef __AMIQ_AES_UVC_CONFIG_OBJ
`define __AMIQ_AES_UVC_CONFIG_OBJ

/*
 * Class: amiq_aes_uvc_config_obj
 * Description: Boilerplate for a future config object if needed.
 */
class amiq_aes_uvc_config_obj extends uvm_object;
  /*
   * Flags: has_coverage
   *
   * Description: Flag used for indicating whether the coverage component is active or not
   */
  bit has_coverage = 1;

  /*
   * Flags: enable_stats_storage
   *
   * Description: Flag used to enable the coverage statistics queue storage
   */
  bit enable_stats_storage = 1;

  /*
   * Flags: toggle_setup_warning_info_error
   *
   * Description: Used to toggle from info=`AES_INFO, warnings=`AES_WARNING to errors=`AES_ERROR on setup of the iv and
   key
   */
  bit[1 : 0] toggle_setup_info_warning_error = `AES_INFO;

  /*
   * Flags: verbosity_level
   *
   * Description: Used to change the verbosity of the uvm_info from the core
   */
  uvm_verbosity verbosity_level = UVM_NONE;

  /*
   * Field: max_same_key_transactions
   *
   * Description: Indicates how many transactions with the same key are allowed
   */
  int unsigned max_same_key_transactions = 15;

  // Registering the fields with the UVM Factory
  `uvm_object_utils_begin(amiq_aes_uvc_config_obj)
    `uvm_field_int(has_coverage,              UVM_ALL_ON)
    `uvm_field_int(enable_stats_storage,      UVM_ALL_ON)
    `uvm_field_int(max_same_key_transactions, UVM_ALL_ON)
  `uvm_object_utils_end

  // Constructor
  function new(string name = "amiq_aes_uvc_config_obj");
    super.new(name);
  endfunction

endclass

`endif
