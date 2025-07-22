////////////////////////////////////////////////////////////////////////////////
// Company:       AMIQ CONSULTING
// Engineer:      Andrei Neleptcu
//
// Description:   AES-UVC - UVC Output Item
////////////////////////////////////////////////////////////////////////////////
`ifndef __AMIQ_AES_UVC_OUTPUT_ITEM
`define __AMIQ_AES_UVC_OUTPUT_ITEM

/*
 * Class: amiq_aes_uvc_output_item
 *
 * Description: Output item for the UVC, acting as a wrapper over a 16 byte output array
 */
class amiq_aes_uvc_output_item extends uvm_sequence_item;

  /*
   * Variable: data
   *
   * Description: Resulting output data of the AES transaction
   */
  rand byte unsigned data [];

  `uvm_object_utils_begin(amiq_aes_uvc_output_item)
    `uvm_field_sarray_int(data, UVM_ALL_ON)
  `uvm_object_utils_end

  // Constraining the item
  constraint transaction_setup_c {
    soft data.size() == 16;
  }

  function new(string name = "amiq_aes_uvc_output_item");
    super.new(name);
  endfunction

  // Converts the information in an output item to a string format
  virtual function string convert2string();
    string message = {"=====================\n",
      $sformatf("DATA: %0h", `AES_UVC_DATA_BIT_LENGTH'({ >> {data}})),
      "\n=====================\n"};

    return message;
  endfunction

  // Print function for Output Item
  virtual function void print();
    `uvm_info(this.get_full_name(), this.convert2string(), UVM_LOW)
  endfunction

endclass

`endif // __AMIQ_AES_UVC_OUTPUT_ITEM

