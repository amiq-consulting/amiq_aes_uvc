////////////////////////////////////////////////////////////////////////////////
// Company:       AMIQ CONSULTING
// Engineer:      Andrei Neleptcu
//
// Description:   AES-UVC - UVC Coverage Collector
////////////////////////////////////////////////////////////////////////////////
`ifndef __AMIQ_AES_UVC_COVERAGE_COLLECTOR
`define __AMIQ_AES_UVC_COVERAGE_COLLECTOR

// Global Coverage Collector - Boilerplate
class amiq_aes_uvc_coverage_collector extends uvm_component;
  // Registering the class with the UVM Factory
  `uvm_component_utils(amiq_aes_uvc_coverage_collector)

  // Analysis port used to receive items from the core
  uvm_analysis_imp#(amiq_aes_uvc_input_item, amiq_aes_uvc_coverage_collector) aes_uvc_input_item_imp;

  /*
   * Field: transactions_without_key_change
   *
   * Description: Number of transactions in which the key did not change
   */
  protected int unsigned _transactions_without_key_change = 0;

  /*
   * Field: transactions_with_same_new_setup
   *
   * Description: Number of transactions in which the new setup was the same as the old one
   */
  protected int unsigned _transactions_with_same_new_setup = 0;

  /*
   * Field: last_aes_item
   *
   * Description: Last aes item containing a new transaction sampled.
   */
  protected amiq_aes_uvc_input_item _last_aes_item;

  /*
   * Field: aes_uvc_config_obj
   *
   * Description: Config object for the aes_uvc
   */
  amiq_aes_uvc_config_obj aes_uvc_config_obj;

  /*
   * Field: key_iv_hash
   *
   * Description: Associative array used to store used pairs of key/iv
   */
  protected amiq_packed_256bit_t _key_iv_hash [amiq_packed_128bit_t];

  /*
   * Field: _key_iv_time_q
   *
   * Description: Queue of *amiq_setup_occurence* type to store when the same key/iv pair occured
   */
  protected amiq_setup_occurence_q_t _key_iv_time_q;

  /*
   * Field: _time_q
   *
   * Description: Queue of times in which the same new setup has occured
   */
  protected amiq_time_q_t _same_setup_q;

  /*
   * Field: packed_key
   *
   * Description: Packed bit value of the key to interact with the *key_iv_hash* associative aray
   */
  protected bit [`AES_UVC_MAX_KEY_BIT_LENGTH - 1 : 0] _packed_key = '{default : 0};

  /*
   * Field: packed_iv
   *
   * Description: Packed bit value of the IV to interact with the *key_iv_hash* associative aray
   */
  protected bit [`AES_UVC_IV_BIT_LENGTH - 1 : 0] _packed_iv = '{default : 0};

  /*
   * Covergroup: key_bytes_cg
   *
   * Description: Covergroup used to sample key's bytes and their index
   *
   * Parameters:
   *  data_byte - Each byte of the key
   *  index - Corresponding index for each byte
   */
  covergroup key_bytes_cg() with function sample(byte unsigned key_byte, int index);
    option.per_instance = 1;
    key_bytes_cp : coverpoint key_byte {
      bins zero                              = {0};
      bins key_bytes_interval_values_1       = {1};
      bins key_bytes_interval_values_2_3     = {[2 : 3]};
      bins key_bytes_interval_values_4_7     = {[4 : 7]};
      bins key_bytes_interval_values_8_15    = {[8 : 15]};
      bins key_bytes_interval_values_16_31   = {[16 : 31]};
      bins key_bytes_interval_values_32_63   = {[32 : 63]};
      bins key_bytes_interval_values_64_127  = {[64 : 127]};
      bins key_bytes_interval_values_128_254 = {[128 : 254]};
      bins max                               = {255};
    }
    index_cp : coverpoint index {
      bins inteval[] = {[0 : 31]};
    }
    key_value_cross : cross key_bytes_cp, index_cp;
  endgroup

  /*
   * Covergroup: data_bytes_cg
   *
   * Description: Covergroup used to sample data's bytes and their index
   *
   * Parameters:
   *  data_byte - Each byte of the state
   *  index - Corresponding index for each byte
   */
  covergroup data_bytes_cg() with function sample(byte unsigned data_byte, int index);
    option.per_instance = 1;
    data_bytes_cp : coverpoint data_byte {
      bins zero                               = {0};
      bins data_bytes_interval_values_1       = {1};
      bins data_bytes_interval_values_2_3     = {[2 : 3]};
      bins data_bytes_interval_values_4_7     = {[4 : 7]};
      bins data_bytes_interval_values_8_15    = {[8 : 15]};
      bins data_bytes_interval_values_16_31   = {[16 : 31]};
      bins data_bytes_interval_values_32_63   = {[32 : 63]};
      bins data_bytes_interval_values_64_127  = {[64 : 127]};
      bins data_bytes_interval_values_128_254 = {[128 : 254]};
      bins max                                = {255};
    }
    index_cp : coverpoint index {
      bins inteval[] = {[0 : 15]};
    }
    data_value_cross : cross data_bytes_cp, index_cp;
  endgroup

  /*
   * Covergroup: iv_bytes_cg
   *
   * Description: Covergroup used to sample IV's bytes and their index
   *
   * Parameters:
   *  data_byte - Each byte of the IV
   *  index - Corresponding index for each byte
   */
  covergroup iv_bytes_cg() with function sample(byte unsigned iv_byte, int index);
    option.per_instance = 1;
    iv_bytes_cp : coverpoint iv_byte {
      bins zero                             = {0};
      bins iv_bytes_interval_values_1       = {1};
      bins iv_bytes_interval_values_2_3     = {[2 : 3]};
      bins iv_bytes_interval_values_4_7     = {[4 : 7]};
      bins iv_bytes_interval_values_8_15    = {[8 : 15]};
      bins iv_bytes_interval_values_16_31   = {[16 : 31]};
      bins iv_bytes_interval_values_32_63   = {[32 : 63]};
      bins iv_bytes_interval_values_64_127  = {[64 : 127]};
      bins iv_bytes_interval_values_128_254 = {[128 : 254]};
      bins max                              = {255};
    }
    index_cp : coverpoint index {
      bins index[] = {[0 : 15]};
    }
    iv_value_cross : cross iv_bytes_cp, index_cp;
  endgroup

  /*
   * Covergroup: setup_information_cg
   *
   * Description: Covergroup used to sample variations from the *amiq_aes_setup* part of the
   * *amiq_aes_uvc_input_item*
   *
   * Parameters:
   *  transaction_setup - field containing all information from *amiq_aes_setup*
   */
  covergroup setup_information_cg() with function sample(amiq_aes_setup transaction_setup);
    option.per_instance = 1;
    key_size_cp : coverpoint transaction_setup.key_size {
      bins \128_bit  = {AES_128};
      bins \192_bit  = {AES_192};
      bins \256_bit  = {AES_256};
    }
    key_size_transitions_cp : coverpoint transaction_setup.key_size {
      bins transitions[] = (AES_128, AES_192, AES_256 => AES_128, AES_192, AES_256 => AES_128, AES_192, AES_256);
    }
    block_mode_cp : coverpoint transaction_setup.block_mode {
      bins ecb     = {AES_ECB};
      bins ctr     = {AES_CTR};
      bins cbc     = {AES_CBC};
      bins ofb     = {AES_OFB};
      bins cfb_1   = {AES_CFB1};
      bins cfb_8   = {AES_CFB8};
      bins cfb_128 = {AES_CFB128};
    }
    block_mode_transitions_cp : coverpoint transaction_setup.block_mode {
      bins transitions[] = (AES_ECB, AES_CTR, AES_CBC, AES_OFB, AES_CFB1, AES_CFB8, AES_CFB128 => AES_ECB, AES_CTR,
        AES_CBC, AES_OFB, AES_CFB1, AES_CFB8, AES_CFB128);
    }
    transaction_type_cp : coverpoint transaction_setup.transaction_type {
      bins encryption = {AES_ENCRYPTION};
      bins decryption = {AES_DECRYPTION};
    }
    transaction_cross : cross key_size_cp, block_mode_cp, transaction_type_cp;
  endgroup

  /*
   * Covergroup: statistics_cg
   *
   * Description: Covergroup used to sample statistics information about the current simulation
   *
   * Parameters:
   *  sample_value - field used to hit each bin from the coverpoints
   */
  covergroup statistics_cg() with function sample(int unsigned sample_value);
    option.per_instance = 1;
    nof_transactions_same_key_cp : coverpoint sample_value {
      bins under_max_value = {`AES_BELOW_THRESHOLD_BIN};
      bins over_max_value  = {`AES_ABOVE_THRESHOLD_BIN};
    }
    same_new_setup_cp : coverpoint sample_value {
      bins number_of_same_new_setup_transactions = {`AES_SAME_SETUP_BIN};
    }
    nof_transactions_same_iv_key_pair_cp : coverpoint sample_value {
      bins number_of_same_iv_key_pair_transactions = {`AES_SAME_KEY_IV_BIN};
    }
  endgroup

  // Constructor
  function new(string name = "amiq_aes_uvc_coverage_collector", uvm_component parent);
    super.new(name, parent);
    aes_uvc_input_item_imp = new("aes_uvc_input_item_imp", this);

    _key_iv_time_q = {};
    _same_setup_q  = {};
    _key_iv_hash   = '{default : 0};

    key_bytes_cg = new();
    key_bytes_cg.set_inst_name("key_bytes_cg");

    data_bytes_cg = new();
    data_bytes_cg.set_inst_name("data_bytes_cg");

    iv_bytes_cg = new();
    iv_bytes_cg.set_inst_name("iv_bytes_cg");

    setup_information_cg = new();
    setup_information_cg.set_inst_name("setup_information_cg");

    statistics_cg = new();
    statistics_cg.set_inst_name("statistics_cg");
  endfunction

  // Build phase
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);

    _last_aes_item = amiq_aes_uvc_input_item::type_id::create("_last_aes_item", this);

    if (!uvm_config_db #(amiq_aes_uvc_config_obj)::get(this, "*", "aes_uvc_config_obj", aes_uvc_config_obj))
      `uvm_fatal(get_type_name(), "Could not get the config object handle.")

  endfunction

  // Write port function
  function void write(amiq_aes_uvc_input_item item);
    amiq_aes_uvc_input_item sample_item      = amiq_aes_uvc_input_item::type_id::create("sample_item", this);
    amiq_setup_occurence    occurence_item   = amiq_setup_occurence::type_id::create("occurence_item", this);
    int                     i;                // Index variable
    int                     sample_item_size; // Sample item size

    if (!$cast(sample_item, item)) begin
      `uvm_error(this.get_full_name(), "Failed to cast received item to sample_item")
    end
    sample_item_size = sample_item.data.size();
    for (i = 0; i < sample_item_size; i++) begin
      data_bytes_cg.sample(sample_item.data[i], i);
    end

    if (sample_item.transaction_setup.new_setup == AES_TRUE) begin

      if (sample_item.transaction_setup.block_mode != AES_ECB) begin
        _packed_key = { >> {sample_item.key}};
        _packed_iv  = { >> {sample_item.iv}};

        if (_key_iv_hash[_packed_iv] == _packed_key) begin
          if (aes_uvc_config_obj.has_coverage == 1) begin
            statistics_cg.sample(`AES_SAME_KEY_IV_BIN);

            if (aes_uvc_config_obj.enable_stats_storage == 1) begin
              occurence_item.iv                = _packed_iv;
              occurence_item.key               = _packed_key;
              occurence_item.transaction_setup = sample_item.transaction_setup;
              occurence_item.sim_time          = $time();
              _key_iv_time_q.push_back(occurence_item);
            end
          end
        end
        else begin
          if (aes_uvc_config_obj.enable_stats_storage == 1) begin
            _key_iv_hash[_packed_iv] = _packed_key;
          end
        end

      end

      if ((sample_item.transaction_setup.block_mode == _last_aes_item.transaction_setup.block_mode) && (
            sample_item.transaction_setup.key_size == _last_aes_item.transaction_setup.key_size) && (
            sample_item.transaction_setup.transaction_type == _last_aes_item.transaction_setup.transaction_type)) begin

        if (aes_uvc_config_obj.has_coverage == 1) begin
          statistics_cg.sample(`AES_SAME_SETUP_BIN);

          if (aes_uvc_config_obj.enable_stats_storage == 1) begin

            _same_setup_q.push_back($time());
          end

        end
        _transactions_with_same_new_setup++;

      end

      if (aes_uvc_config_obj.has_coverage == 1) begin
        for (int i = 0; i < (8 * (sample_item.transaction_setup.key_size + 1)); i++) begin
          key_bytes_cg.sample(sample_item.key[i], i);
        end
        for (int i = 0; i < `AES_UVC_IV_BYTE_LENGTH; i++) begin
          iv_bytes_cg.sample(sample_item.iv[i], i);
        end

        setup_information_cg.sample(sample_item.transaction_setup);
        statistics_cg.sample((_transactions_without_key_change >= aes_uvc_config_obj.max_same_key_transactions) ?
          `AES_BELOW_THRESHOLD_BIN : `AES_ABOVE_THRESHOLD_BIN);
      end
      _transactions_without_key_change = 0;

      if (!$cast(_last_aes_item, sample_item)) begin
        `uvm_error(this.get_full_name(), "Failed to cast sampled item to last aes item")
      end
    end
    _transactions_without_key_change++;
  endfunction

  /*
   * Function: get_number_of_transactions_without_key_change
   *
   * Description: Returns the number of transactions in which the key did not change
   *
   */
  function int unsigned get_number_of_transactions_without_key_change();
    return _transactions_without_key_change;
  endfunction

  /*
   * Function: get_same_key_iv_occurence_stats
   *
   * Description: Returns a queue of *amiq_setup_occurence* which stores when the same key/iv pair occured
   *
   */
  function amiq_setup_occurence_q_t get_same_key_iv_occurence_stats();
    return _key_iv_time_q;
  endfunction

  /*
   * Function: get_same_new_setup_occurence_stats
   *
   * Description: Returns a queue of times in which the same new setup occured
   *
   */
  function amiq_time_q_t get_same_new_setup_occurence_stats();
    return _same_setup_q;
  endfunction

endclass

`endif // __AMIQ_AES_UVC_COVERAGE_COLLECTOR
