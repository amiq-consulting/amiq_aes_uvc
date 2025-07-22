////////////////////////////////////////////////////////////////////////////////
// Company:       AMIQ CONSULTING
// Engineer:      Andrei Neleptcu
//
// Description:   AES-UVC - UVC Main module
////////////////////////////////////////////////////////////////////////////////
`ifndef __AMIQ_AES_UVC
`define __AMIQ_AES_UVC

/*
 * Class: amiq_aes_uvc
 *
 * Description: Main module wrapper handling the uvc item-based port communication
 */
class amiq_aes_uvc extends uvm_component;
  // Registering the class with the UVM Factory
  `uvm_component_utils(amiq_aes_uvc)

  // Declaring ports
  `uvm_analysis_imp_decl(_aes_input_item)

  /*
   * Field: aes_input_item
   *
   * Description: Imp port used for receiving uvc input items
   */
  uvm_analysis_imp_aes_input_item #(amiq_aes_uvc_input_item, amiq_aes_uvc) aes_input_item_imp;

  /*
   * Field: aes_output_item_ap
   *
   * Description: Analysis port used for sending an output item generated
   * in the <aes_input_item_imp>'s write function
   */
  uvm_analysis_port#(amiq_aes_uvc_output_item) aes_output_item_ap;

  /*
   * Field: m_aes_core
   *
   * Description: The core containing the aes implementation
   */
  amiq_aes_uvc_core m_aes_core; //protected

  /*
   * Field: m_aes_coverage_collector
   *
   * Description: The coverage collector of the aes uvc
   */
  amiq_aes_uvc_coverage_collector m_aes_coverage_collector;

  /*
   * Field: m_aes_input_item
   *
   * Description: Item used for storing the received item clone
   */
  protected amiq_aes_uvc_input_item m_aes_input_item;

  /*
   * Field: m_aes_output_item
   *
   * Description: Item sent through the output port
   */
  protected amiq_aes_uvc_output_item m_aes_output_item;

  /*
   * Field: unpacked_output_data
   *
   * Description: Unpacked data vector used for storing the output data
   */
  protected byte unsigned unpacked_output_data[] = '{default : '0};

  /*
   * Field: _last_transaction_setup
   *
   * Description: Store the setup in case of back to back transactions without new setup.
   */
  local amiq_aes_setup _last_transaction_setup;

  function new(string name = "amiq_aes_uvc", uvm_component parent = null);
    super.new(name, parent);

    aes_input_item_imp = new("aes_input_item_imp", this);
    aes_output_item_ap = new("aes_output_item_ap", this);
  endfunction

  /*
   * Function: reset_core
   *
   * Description: Receives an <amiq_aes_uvc_input_item> calls the <aes_core> and sends the result through the
   <aes_output_item_ap>
   *
   * Parameters:
   *  p_aes_input_item - item received from the <aes_input_item_imp>
   */
  function void reset_core();
    m_aes_core.reset_setup();
  endfunction

  /*
   * Function: write_aes_input_item
   *
   * Description: Receives an <amiq_aes_uvc_input_item> calls the <aes_core> and sends the result through the
   <aes_output_item_ap>
   *
   * Parameters:
   *  p_aes_input_item - item received from the <aes_input_item_imp>
   */
  function void write_aes_input_item(amiq_aes_uvc_input_item p_aes_input_item);

    if (!$cast(m_aes_input_item, p_aes_input_item.clone())) begin
      `uvm_fatal(this.get_full_name(), "Could not clone the received input uvc item")
    end

    // Remembering the last transaction setup for successive transactions of the same setup
    if (m_aes_input_item.transaction_setup.new_setup == AES_TRUE) begin
      _last_transaction_setup = m_aes_input_item.transaction_setup;

      // Setting the core's Key
      m_aes_core.set_key(m_aes_input_item.key, m_aes_input_item.transaction_setup.key_size);

      // If the block mode is not ECB (ECB does not require an iv), then set the iv
      if (m_aes_input_item.transaction_setup.block_mode != AES_ECB) begin
        m_aes_core.set_iv(m_aes_input_item.iv);
      end
    end
    else begin
      // If the setup flags indicate that the current transaction does not have a new setup, use the previous one
      m_aes_input_item.transaction_setup = _last_transaction_setup;
    end

    // Choosing the desired block mode based on the transaction setup flags
    m_aes_core.aes_main(m_aes_input_item.data, m_aes_input_item.data.size(),
      m_aes_input_item.transaction_setup.transaction_type,
      m_aes_input_item.transaction_setup.block_mode,
      unpacked_output_data);

    m_aes_output_item = amiq_aes_uvc_output_item::type_id::create("m_aes_output_item", this);

    // Pack the unpacked_output_data into the item and send it through the output port
    m_aes_output_item.data = new[unpacked_output_data.size()];
    m_aes_output_item.data = unpacked_output_data;

    unpacked_output_data.delete();

    aes_output_item_ap.write(m_aes_output_item);

  endfunction

  // Build phase
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    m_aes_core               = amiq_aes_uvc_core::type_id::create("m_aes_core", this);
    m_aes_coverage_collector = amiq_aes_uvc_coverage_collector::type_id::create("m_aes_coverage_collector", this);
    _last_transaction_setup  = amiq_aes_setup::type_id::create("_last_transaction_setup", this);
  endfunction

  // Connect phase
  function void connect_phase(uvm_phase phase);
    super.connect_phase(phase);
    m_aes_core.aes_input_item_ap.connect(m_aes_coverage_collector.aes_uvc_input_item_imp);
  endfunction

  /*
   * Function: get_number_of_transactions_without_key_change
   *
   * Description: Returns the number of transactions in which the key did not change
   *
   */
  function int unsigned get_number_of_transactions_without_key_change();
    return m_aes_coverage_collector.get_number_of_transactions_without_key_change();
  endfunction

  /*
   * Function: get_same_key_iv_occurence_stats
   *
   * Description: Returns a queue of *amiq_setup_occurence* which stores when the same key/iv pair occured
   *
   */
  function amiq_setup_occurence_q_t get_same_key_iv_occurence_stats();
    return m_aes_coverage_collector.get_same_key_iv_occurence_stats();
  endfunction

  /*
   * Function: get_same_new_setup_occurence_stats
   *
   * Description: Returns a queue of times in which the same new setup occured
   *
   */
  function amiq_time_q_t get_same_new_setup_occurence_stats();
    return m_aes_coverage_collector.get_same_new_setup_occurence_stats();
  endfunction

endclass

`endif // __AMIQ_AES_UVC
