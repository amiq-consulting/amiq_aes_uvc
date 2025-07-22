////////////////////////////////////////////////////////////////////////////////
// Company:       AMIQ CONSULTING
// Engineer:      Andrei Neleptcu
//
// Description:   AES-UVC - UVC Package
////////////////////////////////////////////////////////////////////////////////
`ifndef __AMIQ_AES_UVC_PKG
`define __AMIQ_AES_UVC_PKG

/*
 * Class: amiq_aes_uvc_pkg
 *
 * Description: AES UVC package containing all file includes and imports.
 */
package amiq_aes_uvc_pkg;

  // Including UVM macros
  `include "uvm_macros.svh"

  // Importing everything from UVM package
  import uvm_pkg::*;

  // Include files
  `include "amiq_aes_uvc_utils_lib.svh"
  `include "amiq_aes_uvc_config_obj.svh"
  `include "amiq_aes_uvc_input_item.svh"
  `include "amiq_aes_uvc_output_item.svh"
  `include "amiq_aes_uvc_misc_lib.svh"
  `include "amiq_aes_uvc_coverage_collector.svh"
  `include "amiq_aes_uvc_core.svh"
  `include "amiq_aes_uvc.svh"

endpackage

`endif // __AMIQ_AES_UVC_PKG

