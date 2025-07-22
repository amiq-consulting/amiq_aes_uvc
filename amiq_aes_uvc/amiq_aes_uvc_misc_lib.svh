////////////////////////////////////////////////////////////////////////////////
// Company:       AMIQ CONSULTING
// Engineer:      Andrei Neleptcu
//
// Description:   AES-UVC - UVC Miscelaneous
////////////////////////////////////////////////////////////////////////////////
`ifndef __AMIQ_AES_UVC_MISC_LIB
`define __AMIQ_AES_UVC_MISC_LIB

/* --------------------------
 * -----DEBUG FUNCTIONS------
 * --------------------------
 */

/*
 * Function: amiq_aes_print_hex_array_d
 *
 * Description: DEBUG function used to print an array in 16 byte segments
 *
 * Parameters:
 *  ctx: string that will be printed alongside the array, used to show the context
 *  byte_array: the array to be printed
 *  length: the length to be printed, by default byte_array.size()
 */
function string amiq_aes_print_hex_array_d(
    string        ctx,
    byte unsigned byte_array[],
    int           length       = byte_array.size()
  );
  string message;
  message = $sformatf("==%s==", ctx);

  for (int i = 0; i < length; i++) begin
    if ((i % 16) == 0) begin
      message = {message , "\n"};
    end
    message = {message, $sformatf("%0h", byte_array[i])};
  end
  message = {message, "\n\n"};

  return message;
endfunction

/*
 * Function: amiq_aes_print_input_item_d
 *
 * Description: DEBUG function used to print an input uvc item
 *
 * Parameters:
 *  ctx: string that will be printed alongside the array, used to show the context
 *  item: the item to be printed
 *  timestamp: flag that will aditionally print the simulation time if set to 1
 */
function string amiq_aes_print_input_item_d(
    string                  ctx,
    amiq_aes_uvc_input_item item,
    bit                     timestamp = 0
  );
  return $sformatf("==%0s==%0s\n", ctx, {timestamp ? $sformatf("at %0d\n", $stime()) : "\n", item.convert2string()});
endfunction

/*
 * Function: amiq_aes_print_output_item_d
 *
 * Description: Equivalent of <amiq_aes_print_input_item_d> for an output uvc item
 */
function string amiq_aes_print_output_item_d(
    string                   ctx,
    amiq_aes_uvc_output_item item,
    bit                      timestamp = 0
  );
  return $sformatf("==%0s==%0s\n", ctx, {timestamp ? $sformatf("at %0d\n", $stime()) : "\n", item.convert2string()});
endfunction

`endif // __AMIQ_AES_UVC_MISC_LIB

