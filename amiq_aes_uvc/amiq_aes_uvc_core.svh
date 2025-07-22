////////////////////////////////////////////////////////////////////////////////
// Company:       AMIQ CONSULTING
// Engineer:      Andrei Neleptcu
//
// Description:   AES-UVC - UVC Core module - AES implementation
////////////////////////////////////////////////////////////////////////////////

`ifndef __AMIQ_AES_UVC_CORE
`define __AMIQ_AES_UVC_CORE

/*
 * Class: amiq_aes_uvc_core
 *
 * Description: Core component of the uvc that implements the logic for the encryption and decryption of all block modes
 */
class amiq_aes_uvc_core extends uvm_component;
  `uvm_component_utils(amiq_aes_uvc_core)

  /*
   * Field: aes_input_item_ap
   *
   * Description: Analysis port used for sending an input item (to the coverage collector)
   */
  uvm_analysis_port#(amiq_aes_uvc_input_item) aes_input_item_ap;

  /*
   * Constant: S_BOX
   *
   * Description: S-Box table used to substitute values in <key_expansion> and <sub_bytes>
   */
  const byte unsigned S_BOX[256] = '{
    //0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
    'h63, 'h7c, 'h77, 'h7b, 'hf2, 'h6b, 'h6f, 'hc5, 'h30, 'h01, 'h67, 'h2b, 'hfe, 'hd7, 'hab, 'h76,
    'hca, 'h82, 'hc9, 'h7d, 'hfa, 'h59, 'h47, 'hf0, 'had, 'hd4, 'ha2, 'haf, 'h9c, 'ha4, 'h72, 'hc0,
    'hb7, 'hfd, 'h93, 'h26, 'h36, 'h3f, 'hf7, 'hcc, 'h34, 'ha5, 'he5, 'hf1, 'h71, 'hd8, 'h31, 'h15,
    'h04, 'hc7, 'h23, 'hc3, 'h18, 'h96, 'h05, 'h9a, 'h07, 'h12, 'h80, 'he2, 'heb, 'h27, 'hb2, 'h75,
    'h09, 'h83, 'h2c, 'h1a, 'h1b, 'h6e, 'h5a, 'ha0, 'h52, 'h3b, 'hd6, 'hb3, 'h29, 'he3, 'h2f, 'h84,
    'h53, 'hd1, 'h00, 'hed, 'h20, 'hfc, 'hb1, 'h5b, 'h6a, 'hcb, 'hbe, 'h39, 'h4a, 'h4c, 'h58, 'hcf,
    'hd0, 'hef, 'haa, 'hfb, 'h43, 'h4d, 'h33, 'h85, 'h45, 'hf9, 'h02, 'h7f, 'h50, 'h3c, 'h9f, 'ha8,
    'h51, 'ha3, 'h40, 'h8f, 'h92, 'h9d, 'h38, 'hf5, 'hbc, 'hb6, 'hda, 'h21, 'h10, 'hff, 'hf3, 'hd2,
    'hcd, 'h0c, 'h13, 'hec, 'h5f, 'h97, 'h44, 'h17, 'hc4, 'ha7, 'h7e, 'h3d, 'h64, 'h5d, 'h19, 'h73,
    'h60, 'h81, 'h4f, 'hdc, 'h22, 'h2a, 'h90, 'h88, 'h46, 'hee, 'hb8, 'h14, 'hde, 'h5e, 'h0b, 'hdb,
    'he0, 'h32, 'h3a, 'h0a, 'h49, 'h06, 'h24, 'h5c, 'hc2, 'hd3, 'hac, 'h62, 'h91, 'h95, 'he4, 'h79,
    'he7, 'hc8, 'h37, 'h6d, 'h8d, 'hd5, 'h4e, 'ha9, 'h6c, 'h56, 'hf4, 'hea, 'h65, 'h7a, 'hae, 'h08,
    'hba, 'h78, 'h25, 'h2e, 'h1c, 'ha6, 'hb4, 'hc6, 'he8, 'hdd, 'h74, 'h1f, 'h4b, 'hbd, 'h8b, 'h8a,
    'h70, 'h3e, 'hb5, 'h66, 'h48, 'h03, 'hf6, 'h0e, 'h61, 'h35, 'h57, 'hb9, 'h86, 'hc1, 'h1d, 'h9e,
    'he1, 'hf8, 'h98, 'h11, 'h69, 'hd9, 'h8e, 'h94, 'h9b, 'h1e, 'h87, 'he9, 'hce, 'h55, 'h28, 'hdf,
    'h8c, 'ha1, 'h89, 'h0d, 'hbf, 'he6, 'h42, 'h68, 'h41, 'h99, 'h2d, 'h0f, 'hb0, 'h54, 'hbb, 'h16 };

  /*
   * Constant: INV_S_BOX
   *
   * Description: Inverse S-Box table used to substitute values in <key_expansion> and <sub_bytes>
   */
  const byte unsigned INV_S_BOX[256] = '{
    //    0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
    'h52, 'h09, 'h6a, 'hd5, 'h30, 'h36, 'ha5, 'h38, 'hbf, 'h40, 'ha3, 'h9e, 'h81, 'hf3, 'hd7, 'hfb,
    'h7c, 'he3, 'h39, 'h82, 'h9b, 'h2f, 'hff, 'h87, 'h34, 'h8e, 'h43, 'h44, 'hc4, 'hde, 'he9, 'hcb,
    'h54, 'h7b, 'h94, 'h32, 'ha6, 'hc2, 'h23, 'h3d, 'hee, 'h4c, 'h95, 'h0b, 'h42, 'hfa, 'hc3, 'h4e,
    'h08, 'h2e, 'ha1, 'h66, 'h28, 'hd9, 'h24, 'hb2, 'h76, 'h5b, 'ha2, 'h49, 'h6d, 'h8b, 'hd1, 'h25,
    'h72, 'hf8, 'hf6, 'h64, 'h86, 'h68, 'h98, 'h16, 'hd4, 'ha4, 'h5c, 'hcc, 'h5d, 'h65, 'hb6, 'h92,
    'h6c, 'h70, 'h48, 'h50, 'hfd, 'hed, 'hb9, 'hda, 'h5e, 'h15, 'h46, 'h57, 'ha7, 'h8d, 'h9d, 'h84,
    'h90, 'hd8, 'hab, 'h00, 'h8c, 'hbc, 'hd3, 'h0a, 'hf7, 'he4, 'h58, 'h05, 'hb8, 'hb3, 'h45, 'h06,
    'hd0, 'h2c, 'h1e, 'h8f, 'hca, 'h3f, 'h0f, 'h02, 'hc1, 'haf, 'hbd, 'h03, 'h01, 'h13, 'h8a, 'h6b,
    'h3a, 'h91, 'h11, 'h41, 'h4f, 'h67, 'hdc, 'hea, 'h97, 'hf2, 'hcf, 'hce, 'hf0, 'hb4, 'he6, 'h73,
    'h96, 'hac, 'h74, 'h22, 'he7, 'had, 'h35, 'h85, 'he2, 'hf9, 'h37, 'he8, 'h1c, 'h75, 'hdf, 'h6e,
    'h47, 'hf1, 'h1a, 'h71, 'h1d, 'h29, 'hc5, 'h89, 'h6f, 'hb7, 'h62, 'h0e, 'haa, 'h18, 'hbe, 'h1b,
    'hfc, 'h56, 'h3e, 'h4b, 'hc6, 'hd2, 'h79, 'h20, 'h9a, 'hdb, 'hc0, 'hfe, 'h78, 'hcd, 'h5a, 'hf4,
    'h1f, 'hdd, 'ha8, 'h33, 'h88, 'h07, 'hc7, 'h31, 'hb1, 'h12, 'h10, 'h59, 'h27, 'h80, 'hec, 'h5f,
    'h60, 'h51, 'h7f, 'ha9, 'h19, 'hb5, 'h4a, 'h0d, 'h2d, 'he5, 'h7a, 'h9f, 'h93, 'hc9, 'h9c, 'hef,
    'ha0, 'he0, 'h3b, 'h4d, 'hae, 'h2a, 'hf5, 'hb0, 'hc8, 'heb, 'hbb, 'h3c, 'h83, 'h53, 'h99, 'h61,
    'h17, 'h2b, 'h04, 'h7e, 'hba, 'h77, 'hd6, 'h26, 'he1, 'h69, 'h14, 'h63, 'h55, 'h21, 'h0c, 'h7d};

  /*
   * Constant: R_CON
   *
   * Description: Required powers of x in the GF(2^8)
   */
  const byte unsigned R_CON[10] = {
    'h01, 'h02, 'h04, 'h08, 'h10, 'h20, 'h40, 'h80, 'h1b, 'h36 };

  /*
   * Constant: NB
   *
   * Description: Number of columns in the state matrix, always = 4
   */
  const byte unsigned NB = 4;

  /*
   * Field: nk
   *
   * Description: Number of 32 bit words in a key: 4 for 128bit, 6 for 192bit, 8 for 256bit
   */
  protected byte unsigned nk = 4;

  /*
   * Field: nr
   *
   * Description: Number of rounds in the cipher: 10 for 128bit, 12 for 192bit, 14 for 256bit
   */
  protected byte unsigned nr = 10;

  /*
   * Field: key_exp_size
   *
   * Description: Expanded key size from the Rijandel key schedule: 176 for 128bit, 208 for 192bit, 240 for 256bit
   */
  protected byte unsigned key_exp_size = 0;

  /*
   * Field: key
   *
   * Description: key used to encrypt/decrypt the data in AES
   */
  protected byte unsigned key[`AES_UVC_MAX_KEY_BYTE_LENGTH] = '{default : '0};

  /*
   * Field: round_key
   *
   * Description: Expanded key according to the Rijandel key schedule
   */
  protected byte unsigned round_key[`AES_UVC_MIN_KEY_BYTE_LENGTH * 15] = '{default : '0};

  /*
   * Field: iv
   *
   * Description: Initialization vector + nonce used in block modes
   */
  protected byte unsigned iv[`AES_UVC_IV_BYTE_LENGTH] = '{default : '0};

  /*
   * Field: prev_iv
   *
   * Description: Storing the previous value of the Initialization vector ( + nonce )
   */
  protected byte unsigned prev_iv[`AES_UVC_IV_BYTE_LENGTH] = '{default : '0};

  /*
   * Flags: valid_key
   *
   * Description: Flag signaling the key has been set correctly
   */
  local bit valid_key = 0;

  /*
   * Flags: valid_iv
   *
   * Description: Flag signaling the iv has been set correctly
   */
  local bit valid_iv = 0;

  /*
   * Flags: new_setup
   *
   * Description: Flag signaling a new setup has been set
   */
  local amiq_aes_bool_e new_setup = AES_TRUE;

  /*
   * Field: m_aes_config-obj
   *
   * Description: Config Object Handle
   */
  protected amiq_aes_uvc_config_obj m_aes_config_obj;

  // Function: new
  function new(string name = "amiq_aes_uvc_core", uvm_component parent);
    super.new(name, parent);

    aes_input_item_ap = new("aes_input_item_ap", this);
  endfunction

  // Build phase
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);

    if (!uvm_config_db #(amiq_aes_uvc_config_obj)::get(this, "*", "aes_uvc_config_obj", m_aes_config_obj))
      `uvm_fatal(get_type_name(), "Could not get the config object handle.")

  endfunction

  /*
   * Function: key_expansion
   *
   * Description: Computes the derived expanded key from the main key by applying
   * rcon, sbox substitutions and rotating the bytes in the words (32 bit slices)
   */
  protected function void key_expansion();
    byte unsigned i; // Index Variables
    byte unsigned j; // Index Variables
    byte unsigned k; // Index Variables
    byte unsigned q; // Index Variables

    byte unsigned word_result[4]; // Storing the modified word from the secret key

    // The first part of the round key is the original secret key
    for (i = 0; i < (NB * nk); i++) begin
      round_key[i] = key[i];
    end

    // Remaining part of round key is computed using SBOX, RCON and previous values of the round key
    for (i = nk; i < (key_exp_size / NB); i++) begin
      k = (i - 1) * NB;

      // Slicing a previous part of the round key
      for (j = 0; j < NB; j++) begin
        word_result[j] = round_key[k + j];
      end

      /*
       * Applying the rcon and sbox substitution depending on each key size.
       * (after every nk words)
       */
      if ((i % nk) == 0) begin
        for (j = 0; j < NB; j++) begin
          word_result[j] = S_BOX[round_key[k + ((j + 1) % NB)]];
        end
        // Rcon substitution is applied only to the first byte.
        word_result[0] ^= R_CON[(i / nk) - 1];
      end

      // Extra sbox substitution every 4 bytes if key is 256 bit (nk == 8)
      if (nk == (2 * NB)) begin
        if ((i % nk) == NB) begin
          for (j = 0; j < NB; j++) begin
            word_result[j] = S_BOX[round_key[k + j]];
          end
        end
      end

      j = i * NB;
      k = (i - nk) * NB;

      // XOR and append the result to the round key
      for (q = 0; q < NB; q++) begin
        round_key[j + q] = round_key[k + q] ^ word_result[q];
      end
    end
  endfunction

  /*
   * Function: add_round_key
   *
   * Description: XOR'ing the state with a slice of the round_key
   *
   * Parameters:
   *  round - index signaling the number of the current round
   *  state - the data being encrypted/decrypted
   */
  protected function void add_round_key(byte unsigned round, ref byte unsigned state[`AES_UVC_DATA_BYTE_LENGTH]);
    byte unsigned state_length = NB * NB; // Length of state in bytes
    byte unsigned i;                      // Index variable

    for (i = 0; i < state_length ; i++) begin
      state[i] ^= round_key[((state_length) * round) + i];
    end
  endfunction

  /*
   * Function: sub_bytes
   *
   * Description: Substitutes the values in the state with the S_BOX equivalent
   *
   * Parameters:
   *  state - the data being encrypted/decrypted
   */
  protected function void sub_bytes(ref byte unsigned state[`AES_UVC_DATA_BYTE_LENGTH]);
    byte unsigned state_length = NB * NB; // Length of state in bytes
    byte unsigned i;                      // Index variable

    for (i = 0; i < state_length; i++) begin
      state[i] = S_BOX[state[i]];
    end
  endfunction

  /*
   * Function: inv_sub_bytes
   *
   * Description: Inverse process of <sub_bytes>
   *
   * Parameters:
   *  state - the data being encrypted/decrypted
   */
  protected function void inv_sub_bytes(ref byte unsigned state[`AES_UVC_DATA_BYTE_LENGTH]);
    byte unsigned state_length = NB * NB; // Length of state in bytes
    byte unsigned i;                      // Index variable

    for (i = 0; i < state_length; i++) begin
      state[i] = INV_S_BOX[state[i]];
    end
  endfunction

  /*
   * Function: shift_rows
   *
   * Description: Shifts first 3 columns to the left
   *
   * Parameters:
   *  state - the data being encrypted/decrypted
   */
  protected function void shift_rows(ref byte unsigned state[`AES_UVC_DATA_BYTE_LENGTH]);
    byte unsigned swap_variable; // Variable used for swapping data
    byte unsigned i;             //Line index
    byte unsigned j;             //Column index

    // Shift all rows circularly with the row's index positions to the left
    for (i = 0; i < NB; i++) begin

      // Repeat i times (Shift by 1 position) = Shift by i positions
      repeat (i) begin

        // Shift by 1 position
        swap_variable = state[i];
        for (j = 0; j < (NB - 1); j++) begin
          state[(j * NB) + i] = state[((j + 1) * NB) + i];
        end
        state[(NB * (NB - 1)) + i] = swap_variable;

      end
    end
  endfunction

  /*
   * Function: inv_shift_rows
   *
   * Description: Inverse process of <shift_rows>
   *
   * Parameters:
   *  state - the data being encrypted/decrypted
   */
  protected function void inv_shift_rows(ref byte unsigned state[`AES_UVC_DATA_BYTE_LENGTH]);
    byte unsigned swap_variable; // Variable used for swapping data
    byte unsigned i;             //Line index
    byte unsigned j;             //Column index

    // Shift all rows circularly with the row's index positions to the right
    for (i = 0; i < NB; i++) begin

      // Repeat i times (Shift by 1 position) = Shift by i positions
      repeat (i) begin

        // Shift by 1 position
        swap_variable = state[12 + i];
        for (j = unsigned'(NB - 1); j >= 1; j--) begin
          state[(j * NB) + i] = state[((j - 1) * NB) + i];
        end
        state[i] = swap_variable;

      end
    end

  endfunction

  /*
   * Function: mix_columns
   *
   * Description: Mixing the columns of the state by GF(2^8) matrix multiplicaton
   *
   * Parameters:
   *  state - the data being encrypted/decrypted
   */
  protected function void mix_columns(ref byte unsigned state[`AES_UVC_DATA_BYTE_LENGTH]);
    byte unsigned i;                 // Index variable
    byte unsigned column_xor;        // The result after XOR'ing all the elements from a column inside the state
    byte unsigned first_column_byte; // First element in a column

    for (i = 0; i < NB; i++) begin
      first_column_byte = state[(i * NB)];
      column_xor        = state[(i * NB)] ^ state[(i * NB) + 1] ^ state[(i * NB) + 2] ^ state[(i * NB) + 3];

      state[(i * NB)]     ^= xtime(state[(i * NB)] ^ state[(i * NB) + 1]) ^ column_xor;
      state[(i * NB) + 1] ^= xtime(state[(i * NB) + 1] ^ state[(i * NB) + 2]) ^ column_xor;
      state[(i * NB) + 2] ^= xtime(state[(i * NB) + 2] ^ state[(i * NB) + 3]) ^ column_xor;
      state[(i * NB) + 3] ^= xtime(state[(i * NB) + 3] ^ first_column_byte) ^ column_xor;
    end

  endfunction

  /*
   * Function: inv_mix_columns
   *
   * Description: Inverse process of <mix_columns>
   *
   * Parameters:
   *  state - the data being encrypted/decrypted
   */
  protected function void inv_mix_columns(ref byte unsigned state[`AES_UVC_DATA_BYTE_LENGTH]);
    byte unsigned lines[4]; // Elements from a line in the state
    byte unsigned i;

    /* 4x4 matrix multiplication in GF(256). Multiplication becomes gf_multiply (function that implements polynomial
     multiplication)
     * and addition becomes XOR.
     */
    for (i = 0; i < NB; i++) begin
      lines = {state[(i * NB)], state[(i * NB) + 1], state[(i * NB) + 2], state[(i * NB) + 3]};

      state[(i * NB)] = gf_multiply(lines[0], 'h0e) ^ gf_multiply(lines[1], 'h0b) ^ gf_multiply(lines[2], 'h0d) ^
        gf_multiply(lines[3], 'h09);
      state[(i * NB) + 1] = gf_multiply(lines[0], 'h09) ^ gf_multiply(lines[1], 'h0e) ^ gf_multiply(lines[2], 'h0b) ^
        gf_multiply(lines[3], 'h0d);
      state[(i * NB) + 2] = gf_multiply(lines[0], 'h0d) ^ gf_multiply(lines[1], 'h09) ^ gf_multiply(lines[2], 'h0e) ^
        gf_multiply(lines[3], 'h0b);
      state[(i * NB) + 3] = gf_multiply(lines[0], 'h0b) ^ gf_multiply(lines[1], 'h0d) ^ gf_multiply(lines[2], 'h09) ^
        gf_multiply(lines[3], 'h0e);
    end

  endfunction

  /*
   * Function: gf_multiply
   *
   * Description: Multiplication of 2 bytes in GF(2^8) (2 polynomials)
   *
   * Parameters:
   *  x - term 1
   *  y - term 2
   */
  protected function byte unsigned gf_multiply(byte unsigned x, byte unsigned y);
    return (((y & 1) * x) ^ (((y >> 1) & 1) * xtime(x)) ^ (((y >> 2) & 1) * xtime(xtime(x))) ^ (((y >> 3) & 1) * xtime(
          xtime(xtime(x)))) ^ (((y >> 4) & 1) * xtime(xtime(xtime(xtime(x))))));
  endfunction

  /*
   * Function: xtime
   *
   * Description: Multiplication by 2 in GF(2^8)
   *
   * Parameters:
   *  x - term
   */
  protected function byte unsigned xtime(byte unsigned x);
    return ((x << 1) ^ (((x >> 7) & 1) * 'h1b));
  endfunction

  /*
   * Function: cipher
   *
   * Description: Main algorithm of the AES Encryption - the ECB mode
   *
   * Parameters:
   *  state - the data being encrypted/decrypted
   */
  protected function void cipher(ref byte unsigned state[`AES_UVC_DATA_BYTE_LENGTH]);
    byte unsigned round = 0;

    add_round_key(0, state);

    for (round = 1; round < nr; round++) begin
      sub_bytes(state);
      shift_rows(state);
      mix_columns(state);
      add_round_key(round, state);
    end

    sub_bytes(state);
    shift_rows(state);

    add_round_key(nr, state);
  endfunction

  /*
   * Function: inv_cipher
   *
   * Description: Main algorithm of the AES Decryption - the ECB mode
   *
   * Parameters:
   *  state - the data being encrypted/decrypted
   */
  protected function void inv_cipher(ref byte unsigned state[`AES_UVC_DATA_BYTE_LENGTH]);
    byte unsigned round = 0;

    add_round_key(nr, state);

    for (round = unsigned'(nr - 1); round > 0; round--) begin
      inv_shift_rows(state);
      inv_sub_bytes(state);
      add_round_key(round, state);
      inv_mix_columns(state);
    end

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(0, state);

  endfunction

  /*
   * Function: increment_iv
   *
   * Description: Function that increments the iv by 1 and handles overflows
   */
  protected function void increment_iv();
    // Handle the individual byte overflow in the iv++ operation
    for (int i = `AES_UVC_IV_BYTE_LENGTH - 1; i >= 0; i--) begin
      // If the value of a byte is 255, set it to 0 and continue to the next iteration
      if (iv[i] == `AES_MAX_BYTE_VALUE) begin
        iv[i] = 0;
        continue;
      end
      // If there is no overflow add 1 (also takes care of the carry from a previous overflow) and then exit
      iv[i] = iv[i] + unsigned'(1);
      break;
    end
  endfunction

  /*
   * Function: send_to_coverage
   *
   * Description: Function that build an *amiq_aes_uvc_input_item* and sends it through *aes_input_item_ap*
   * to the coverage collector
   *
   * Parameters:
   *  state - the data being encrypted/decrypted
   *  state_size - the size of the state
   *  operation - either AES_ENCRYPTION or AES_DECRYPTION
   *  block_mode - the block mode chosen
   */
  protected function void send_to_coverage(
      input byte unsigned              state[],
      input int unsigned               state_size,
      input amiq_aes_encrypt_decrypt_e operation,
      input amiq_aes_block_mode_e      block_mode
    );

    amiq_aes_uvc_input_item aes_coverage_item = amiq_aes_uvc_input_item::type_id::create("aes_coverage_item", this);

    aes_coverage_item.data                               = new[state_size];
    aes_coverage_item.data                               = state;
    aes_coverage_item.key                                = key;
    aes_coverage_item.iv                                 = iv;
    aes_coverage_item.transaction_setup.block_mode       = block_mode;
    aes_coverage_item.transaction_setup.transaction_type = operation;
    aes_coverage_item.transaction_setup.key_size         = amiq_aes_key_size_e'((nk / 2) - 1);
    aes_coverage_item.transaction_setup.new_setup        = new_setup;

    aes_input_item_ap.write(aes_coverage_item);

  endfunction

  /*
   * ----------------------------------------------
   * PUBLIC FUNCTIONS
   * ----------------------------------------------
   */

  /*
   * Function: reset_setup
   *
   * Description: Resets the valid key and valid iv flags
   */
  function void reset_setup();
    valid_key = 0;
    valid_iv  = 0;
  endfunction

  /*
   * Function: set_key
   *
   * Description: Setting the key used for the transactions
   *
   * Parameters:
   *  new_key - the key being set
   *  size - the size of the said key
   */
  function void set_key(byte unsigned new_key[], amiq_aes_key_size_e size);

    valid_key = 0;
    new_setup = AES_TRUE;

    if ((size == AES_128) || (size == AES_192) || (size == AES_256)) begin
      if (new_key.size() >= (`AES_UVC_MIN_KEY_BYTE_LENGTH + (8 * (size - 1)))) begin
        valid_key = 1;
      end
    end

    if (valid_key == 1) begin
      nk           = 2 * (size + 1);
      nr           = nk + unsigned'(6);
      key_exp_size = `AES_UVC_MIN_KEY_BYTE_LENGTH * (nr + 1);

      for (int i = 0; i < ((size + 1) * `AES_UVC_BYTE); i++) begin
        key[i] = new_key[i];
      end

      key_expansion();
    end
    else begin
      `uvm_info(this.get_full_name(), $sformatf(
          "Incorrect key length, needed:128/192/256bits(16/24/32bytes), actual:%dbits(%d bytes)", new_key.size * 8,
          new_key.size), UVM_NONE)
    end

  endfunction

  /*
   * Function: set_iv
   *
   * Description: Setting the iv used for the transactions
   *
   * Parameters:
   *  new_IV - the iv being set
   *  size - the size of the said iv
   */
  function void set_iv(byte unsigned new_iv[], int size = new_iv.size);

    valid_iv  = 0;
    new_setup = AES_TRUE;
    if (size == `AES_UVC_IV_BYTE_LENGTH) begin
      valid_iv = 1;

      for (int i = 0; i < `AES_UVC_IV_BYTE_LENGTH; i++) begin
        iv[i] = new_iv[i];
      end
    end
    else begin
      `uvm_info(this.get_full_name(), $sformatf("Incorrect iv length, needed:128bits(16 bytes), actual:%dbits(%d bytes)"
          , size * 8, size), UVM_NONE)
    end

  endfunction

  /*
   * Function: call_failure
   *
   * Description: Chooses between uvm info or uvm error based on the config object flag
   *
   * Parameters:
   *  ctx - context of the message
   *  verbosity - verbosity desired, defaults to the verbosity level from the config obj.
   */
  function void call_failure(
      string        ctx,
      string        message,
      uvm_verbosity verbosity = m_aes_config_obj.verbosity_level
    );
    case (m_aes_config_obj.toggle_setup_info_warning_error)
      `AES_INFO    : `uvm_info(ctx, message, verbosity)
      `AES_WARNING : `uvm_warning(ctx, message)
      `AES_ERROR   : `uvm_error(ctx, message)
      default      : `uvm_error(this.get_full_name(), "received illegal parameter")
    endcase;
  endfunction

  /*
   * Function: encrypt_ecb
   *
   * Description: User function for ECB Encryption
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   */
  function void encrypt_ecb(
      input  byte unsigned state[],
      input  int unsigned  state_size,
      output byte unsigned output_data[],
      input  byte unsigned missing_bits_in_last_byte = 0
    );

    byte unsigned state_copy[`AES_UVC_DATA_BYTE_LENGTH];
    int           state_remainder_size                  = state_size % `AES_UVC_DATA_BYTE_LENGTH;
    int           state_rounded_size                    = state_size - state_remainder_size;

    if (valid_key == 1) begin

      output_data = new[state_rounded_size + ((state_remainder_size > 0 )? `AES_UVC_DATA_BYTE_LENGTH : 0)];

      for (int i = 0; i < state_rounded_size; i += `AES_UVC_DATA_BYTE_LENGTH) begin
        state_copy = state[i +: `AES_UVC_DATA_BYTE_LENGTH];

        cipher(state_copy);
        output_data[i +: `AES_UVC_DATA_BYTE_LENGTH] = state_copy;
      end

      if (state_remainder_size > 0) begin

        for (int i = 0; i < state_remainder_size; i++) begin
          state_copy[i] = state[state_rounded_size + i];
        end
        if (missing_bits_in_last_byte != 0) begin
          state_copy[state_remainder_size - 1][missing_bits_in_last_byte - 1] = 1;
          for (int i = int'(missing_bits_in_last_byte) - 2; i >= 0; i--) begin
            state_copy[state_remainder_size - 1][i] = 0;
          end
          state_copy[state_remainder_size] = 0;

        end
        else begin
          state_copy[state_remainder_size] = `AES_UVC_PAD_BYTE;
        end
        for (int i = state_remainder_size + 1; i < `AES_UVC_DATA_BYTE_LENGTH; i++) begin
          state_copy[i] = 0;
        end

        cipher(state_copy);
        output_data[state_rounded_size +: `AES_UVC_DATA_BYTE_LENGTH] = state_copy;
      end
    end
    else begin
      output_data = state;
      call_failure(this.get_full_name(), $sformatf(
          "Invalid Setup - cannot start processing ENCRYPTION for ECB: valid_key=%0d", valid_key));
    end

  endfunction

  /*
   * Function: decrypt_ecb
   *
   * Description: User function for ECB Decryption
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   */
  function void decrypt_ecb(
      input  byte unsigned state[],
      input  int unsigned  state_size,
      output byte unsigned output_data[]
    );

    byte unsigned state_copy[`AES_UVC_DATA_BYTE_LENGTH];
    int           state_rounded_size                    = state_size;
    int           state_remainder_size                  = state_size % `AES_UVC_DATA_BYTE_LENGTH;

    state_rounded_size = state_rounded_size - state_remainder_size;

    if (valid_key == 1) begin
      if (state_remainder_size > 0) begin
        call_failure(this.get_full_name(), $sformatf(
            "ECB Decryption requires the state to be a multiple of 16 bytes (128 bits), size is:%0d bytes", state_size))
        ;
      end

      output_data = new[state_rounded_size];

      for (int i = 0; i < state_rounded_size; i += `AES_UVC_DATA_BYTE_LENGTH) begin
        state_copy = state[i +: `AES_UVC_DATA_BYTE_LENGTH];
        inv_cipher(state_copy);
        output_data[i +: `AES_UVC_DATA_BYTE_LENGTH] = state_copy;
      end
    end
    else begin
      output_data = state;
      call_failure(this.get_full_name(), $sformatf(
          "Invalid Setup - cannot start processing DECRYPTION for ECB: valid_key=%0d", valid_key));
    end

  endfunction

  /*
   * Function: xcrypt_ecb
   *
   * Description: User function for ECB X-Cryption (Wrapper for both Encryption and Decryption)
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   *  operation - AES_ENCRYPTION or AES_DECRYPTION
   */
  function void xcrypt_ecb(
      input  byte unsigned              state[],
      input  int unsigned               state_size,
      input  amiq_aes_encrypt_decrypt_e operation,
      output byte unsigned              output_data[],
      input  byte unsigned              missing_bits_in_last_byte = 0
    );

    if (valid_key == 1) begin

      if (m_aes_config_obj.has_coverage == 1) begin
        send_to_coverage(state, state_size, operation, AES_ECB);
      end

      case (operation)
        AES_ENCRYPTION : begin
          encrypt_ecb(state, state_size, output_data, missing_bits_in_last_byte);
        end
        AES_DECRYPTION : begin
          decrypt_ecb(state, state_size, output_data);
        end
        default: begin
          `uvm_error(this.get_full_name(), "Undefined state!")
        end
      endcase;
      new_setup = AES_FALSE;
    end
    else begin
      output_data = state;
      call_failure(this.get_full_name(), $sformatf("Invalid Setup - cannot start processing %0s for ECB: valid_key=%0d"
          , operation.name(), valid_key));
    end

  endfunction

  /*
   * Function: xcrypt_ctr
   *
   * Description: User function for CTR X-Cryption (Both Encryption and Decryption are the same)
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   */
  function void xcrypt_ctr(
      input  byte unsigned              state[],
      input  int unsigned               state_size,
      input  amiq_aes_encrypt_decrypt_e operation,
      output byte unsigned              output_data[]
    );

    byte unsigned state_copy[`AES_UVC_DATA_BYTE_LENGTH];
    int           state_rounded_size                    = state_size;
    int           state_remainder_size                  = state_size % `AES_UVC_DATA_BYTE_LENGTH;

    state_rounded_size = state_rounded_size - state_remainder_size;

    if ((valid_key == 1) && (valid_iv == 1)) begin

      if (m_aes_config_obj.has_coverage == 1) begin
        send_to_coverage(state, state_size, operation, AES_CTR);
      end

      output_data = new[state_rounded_size + state_remainder_size];

      for (int i = 0; i < state_rounded_size; i += `AES_UVC_DATA_BYTE_LENGTH) begin
        output_data[i +: `AES_UVC_DATA_BYTE_LENGTH] = state[i +: `AES_UVC_DATA_BYTE_LENGTH];

        prev_iv = iv;

        cipher(prev_iv);

        for (int j = i; j < (i + `AES_UVC_IV_BYTE_LENGTH); j++) begin
          output_data[j] ^= prev_iv[j - i];
        end

        increment_iv();
      end

      if (state_remainder_size > 0) begin

        for (int i = 0; i < state_remainder_size; i++) begin
          state_copy[i] = state[state_rounded_size + i];
        end

        prev_iv = iv;

        cipher(prev_iv);

        for (int j = state_rounded_size; j < (state_rounded_size + state_remainder_size); j++) begin
          output_data[j] = state_copy[j - state_rounded_size] ^ prev_iv[j - state_rounded_size];
        end

        increment_iv();
      end
      new_setup = AES_FALSE;
    end
    else begin
      output_data = state;
      call_failure(this.get_full_name(), $sformatf(
          "Invalid Setup - cannot start processing CTR X-Cryption, valid_key=%0d, valid_iv=%0d", valid_key, valid_iv));
    end

  endfunction

  /*
   * Function: encrypt_cbc
   *
   * Description: User function for CBC Encryption
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   */
  function void encrypt_cbc(
      input  byte unsigned state[],
      input  int unsigned  state_size,
      output byte unsigned output_data[],
      input  byte unsigned missing_bits_in_last_byte = 0
    );

    byte unsigned state_copy[`AES_UVC_DATA_BYTE_LENGTH];
    int           state_rounded_size                    = state_size;
    int           state_remainder_size                  = state_size % `AES_UVC_DATA_BYTE_LENGTH;

    if ((valid_key == 1) && (valid_iv == 1)) begin
      state_rounded_size = state_rounded_size - state_remainder_size;

      output_data = new[state_rounded_size + ((state_remainder_size > 0) ? `AES_UVC_DATA_BYTE_LENGTH : 0)];

      for (int i = 0; i < state_rounded_size; i += `AES_UVC_DATA_BYTE_LENGTH) begin
        state_copy = state[i +: `AES_UVC_DATA_BYTE_LENGTH];

        for (int i = 0; i < `AES_UVC_IV_BYTE_LENGTH; i++) begin
          state_copy[i] ^= iv[i];
        end

        cipher(state_copy);

        iv = state_copy;

        output_data[i +: `AES_UVC_DATA_BYTE_LENGTH] = state_copy;
      end

      if (state_remainder_size > 0) begin

        for (int i = 0; i < `AES_UVC_IV_BYTE_LENGTH; i++) begin
          state_copy[i] = iv[i];
        end

        for (int i = 0; i < state_remainder_size; i++) begin
          state_copy[i] ^= state[state_rounded_size + i];
        end

        if (missing_bits_in_last_byte != 0) begin
          state_copy[state_remainder_size - 1][missing_bits_in_last_byte - 1] ^= 1;
        end
        else begin
          state_copy[state_remainder_size] ^= `AES_UVC_PAD_BYTE;
        end

        cipher(state_copy);

        iv = state_copy;

        output_data[state_rounded_size +: `AES_UVC_DATA_BYTE_LENGTH] = state_copy;

      end
    end
    else begin
      call_failure(this.get_full_name(), $sformatf(
          "Invalid Setup - cannot start processing ENCRYPTION for CBC, valid_key=%0d, valid_iv=%0d", valid_key,
          valid_iv));
    end

  endfunction

  /*
   * Function: decrypt_cbc
   *
   * Description: User function for CBC Decryption
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   */
  function void decrypt_cbc(
      input  byte unsigned state[],
      input  int unsigned  state_size,
      output byte unsigned output_data[]
    );

    byte unsigned state_copy[`AES_UVC_DATA_BYTE_LENGTH];
    int           state_rounded_size                    = state_size;
    int           state_remainder_size                  = state_size % `AES_UVC_DATA_BYTE_LENGTH;

    if ((valid_key == 1) && (valid_iv == 1)) begin
      state_rounded_size = state_rounded_size - state_remainder_size;

      if (state_remainder_size > 0) begin
        call_failure(this.get_full_name(), $sformatf(
            "CBC Decryption requires the state to be a multiple of 16 bytes (128 bits), size is:%0d bytes", state_size))
        ;
      end

      output_data = new[state_rounded_size];

      for (int i = 0; i < state_rounded_size; i += `AES_UVC_DATA_BYTE_LENGTH) begin
        prev_iv    = state[i +: `AES_UVC_DATA_BYTE_LENGTH];
        state_copy = state[i +: `AES_UVC_DATA_BYTE_LENGTH];

        inv_cipher(state_copy);

        for (int j = i; j < (i + `AES_UVC_IV_BYTE_LENGTH); j++) begin
          output_data[j] = state_copy[j - i] ^ iv[j - i];
        end

        iv = prev_iv;
      end
    end
    else begin
      call_failure(this.get_full_name(), $sformatf(
          "Invalid Setup - cannot start processing DECRYPTION for CBC, valid_key=%0d, valid_iv=%0d", valid_key,
          valid_iv));
    end

  endfunction

  /*
   * Function: xcrypt_cbc
   *
   * Description: User function for CBC X-Cryption (Wrapper for both Encryption and Decryption)
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   *  operation - AES_ENCRYPTION or AES_DECRYPTION
   */
  function void xcrypt_cbc(
      input  byte unsigned              state[],
      input  int unsigned               state_size,
      input  amiq_aes_encrypt_decrypt_e operation,
      output byte unsigned              output_data[],
      input  byte unsigned              missing_bits_in_last_byte = 0
    );

    if ((valid_key == 1) && (valid_iv == 1)) begin

      if (m_aes_config_obj.has_coverage == 1) begin
        send_to_coverage(state, state_size, operation, AES_CBC);
      end

      case (operation)
        AES_ENCRYPTION : begin
          encrypt_cbc(state, state_size, output_data, missing_bits_in_last_byte);
        end
        AES_DECRYPTION : begin
          decrypt_cbc(state, state_size, output_data);
        end
        default: begin
          `uvm_error(this.get_full_name(), "Undefined state!")
        end
      endcase;
      new_setup = AES_FALSE;
    end
    else begin
      call_failure(this.get_full_name(), $sformatf(
          "Invalid Setup - cannot start processing %s CBC, valid_key=%0d, valid_iv=%0d", operation.name(), valid_key,
          valid_iv));
    end
  endfunction

  /*
   * Function: xcrypt_ofb
   *
   * Description: User function for OFB X-Cryption (Both Encryption and Decryption are the same)
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   */
  function void xcrypt_ofb(
      input  byte unsigned              state[],
      input  int unsigned               state_size,
      input  amiq_aes_encrypt_decrypt_e operation,
      output byte unsigned              output_data[],
      input  byte unsigned              missing_bits_in_last_byte = 0
    );
    int state_rounded_size   = state_size;
    int state_remainder_size = state_size % `AES_UVC_DATA_BYTE_LENGTH;

    state_rounded_size = state_rounded_size - state_remainder_size;

    if ((valid_key == 1) && (valid_iv == 1)) begin

      if (m_aes_config_obj.has_coverage == 1) begin
        send_to_coverage(state, state_size, operation, AES_OFB);
      end

      output_data = new[state_rounded_size + state_remainder_size];

      for (int i = 0; i < state_rounded_size; i += `AES_UVC_DATA_BYTE_LENGTH) begin
        output_data[i +: `AES_UVC_DATA_BYTE_LENGTH] = state[i +: `AES_UVC_DATA_BYTE_LENGTH];

        cipher(iv);

        for (int j = i; j < (i + `AES_UVC_IV_BYTE_LENGTH); j++) begin
          output_data[j] ^= iv[j - i];
        end

      end

      if (state_remainder_size > 0) begin
        cipher(iv);

        for (int j = state_rounded_size; j < (state_rounded_size + state_remainder_size); j++) begin
          output_data[j] = state[j] ^ iv[j - state_rounded_size];
        end

        if (missing_bits_in_last_byte > 0) begin
          output_data[state_rounded_size + state_remainder_size - 1][missing_bits_in_last_byte - 1] = 1 ^ iv[
              state_remainder_size - 1][missing_bits_in_last_byte - 1];
          for (int j = int'(missing_bits_in_last_byte) - 2; j >= 0; j--) begin
            output_data[state_rounded_size + state_remainder_size - 1][j] = iv[state_remainder_size - 1][j];
          end
        end
      end
      new_setup = AES_FALSE;
    end
    else begin
      call_failure(this.get_full_name(), $sformatf(
          "Invalid Setup - cannot start processing OFB X-Cryption, valid_key=%0d, valid_iv=%0d", valid_key, valid_iv))
      ;
    end

  endfunction

  /*
   * Function: xcrypt_cfb
   *
   * Description: User function for CFB X-Cryption (Both Encryption and Decryption are very similar)
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   *  operation - either AES_ENCRYPTION or AES_DECRYPTION
   *  cfb_type - AES_CFB1, AES_CFB8 or AES_CFB128
   */
  function void xcrypt_cfb(
      input  byte unsigned              state[],
      input  int unsigned               state_size,
      input  amiq_aes_encrypt_decrypt_e operation,
      input  amiq_aes_block_mode_e      cfb_type,
      output byte unsigned              output_data[]
    );

    bit [`AES_UVC_DATA_BIT_LENGTH - 1 : 0] plain_text;   // Packed bit array as CFB works on bit offsets
    bit [`AES_UVC_DATA_BIT_LENGTH - 1 : 0] cipher_text;  // Packed bit array as CFB works on bit offsets
    bit [`AES_UVC_DATA_BIT_LENGTH - 1 : 0] output_block; // Packed bit array as CFB works on bit offsets
    bit [`AES_UVC_DATA_BIT_LENGTH - 1 : 0] input_block;  // Packed bit array as CFB works on bit offsets
    byte unsigned                          cfb_offset = (cfb_type == AES_CFB1) ? 1 : ((cfb_type == AES_CFB8) ? 8 : 128);
    int                                    state_rounded_size = state_size;
    int                                    state_remainder_size = state_size % `AES_UVC_DATA_BYTE_LENGTH;

    state_rounded_size = state_rounded_size - state_remainder_size;

    if ((valid_key == 1) && (valid_iv == 1)) begin

      if (m_aes_config_obj.has_coverage == 1) begin
        send_to_coverage(state, state_size, operation, cfb_type);
      end

      output_data = new[state_rounded_size + state_remainder_size];

      for (int k = 0; k < state_rounded_size; k += `AES_UVC_DATA_BYTE_LENGTH) begin
        plain_text = { >> {state[k +: `AES_UVC_DATA_BYTE_LENGTH]}};

        for (int i = 127; i >= 0; i = i - int'(cfb_offset)) begin

          input_block = { >> {iv}};
          cipher(iv);
          output_block = { >> {iv}};

          // Depending on the CFB offset, the next iv is prepared accordingly through bit slicing while also computing
          // the ciphertext
          case (cfb_type)
            AES_CFB1 : begin
              cipher_text[i] = output_block[127] ^ plain_text[i];
              { >> {iv}}     = {input_block[126 : 0], (operation == AES_ENCRYPTION) ? cipher_text[i] : plain_text[i]};
            end
            AES_CFB8 : begin
              cipher_text[i -: 8] = output_block[127 -: 8] ^ plain_text[i -: 8];
              { >> {iv}} = {input_block[119 : 0], (operation == AES_ENCRYPTION) ? cipher_text[i -: 8] : plain_text[i -:
                  8]};
            end
            AES_CFB128 : begin
              cipher_text = output_block ^ plain_text;
              { >> {iv}}  = (operation == AES_ENCRYPTION) ? cipher_text : plain_text;
            end
            default: begin
              `uvm_error(this.get_full_name(), "Undefined state!")
            end
          endcase;
        end
        { >> {output_data[k +: `AES_UVC_DATA_BYTE_LENGTH]}} = cipher_text;
      end

      for (int i = 0; i < state_remainder_size; i++) begin
        plain_text[(127 - (i * 8)) -: 8] = state[state_rounded_size + i];
      end

      for (int i = 127; i >= (128 - (state_remainder_size * 8)); i = i - int'(cfb_offset)) begin
        input_block = { >> {iv}};
        cipher(iv);
        output_block = { >> {iv}};

        // Depending on the CFB offset, the next iv is prepared accordingly through bit slicing while also computing the
        // ciphertext
        case (cfb_type)
          AES_CFB1 : begin
            cipher_text[i] = output_block[127] ^ plain_text[i];
            { >> {iv}}     = {input_block[126 : 0], (operation == AES_ENCRYPTION) ? cipher_text[i] : plain_text[i]};
          end
          AES_CFB8 : begin
            cipher_text[i -: 8] = output_block[127 -: 8] ^ plain_text[i -: 8];
            { >> {iv}} = {input_block[119 : 0], (operation == AES_ENCRYPTION) ? cipher_text[i -: 8] : plain_text[i -: 8]
            };
          end
          AES_CFB128 : begin
            cipher_text = output_block ^ plain_text;
            { >> {iv}}  = (operation == AES_ENCRYPTION) ? cipher_text : plain_text;
          end
          default: begin
            `uvm_error(this.get_full_name(), "Undefined state!")
          end
        endcase;
      end
      for (int i = state_rounded_size; i < (state_rounded_size + state_remainder_size); i++) begin
        { >> {output_data[i]}} = cipher_text[(127 - (i * 8)) -: 8];
      end
      new_setup = AES_FALSE;
    end
    else begin
      call_failure(this.get_full_name(), $sformatf(
          "Invalid Setup - cannot start processing %0s %0s, valid_key=%0d, valid_iv=%0d", cfb_type.name(),
          operation.name( ), valid_key, valid_iv));
    end
  endfunction

  /*
   * Function: encrypt_cfb1
   *
   * Description: User function for CFB Encryption with 1 bit offset
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   */
  function void encrypt_cfb1(
      input  byte unsigned state[],
      input  int unsigned  state_size,
      output byte unsigned output_data[]
    );

    xcrypt_cfb(state, state_size, AES_ENCRYPTION, AES_CFB1, output_data);
  endfunction

  /*
   * Function: decrypt_cfb1
   *
   * Description: User function for CFB Decryption with 1 bit offset
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   */
  function void decrypt_cfb1(
      input  byte unsigned state[],
      input  int unsigned  state_size,
      output byte unsigned output_data[]
    );

    xcrypt_cfb(state, state_size, AES_DECRYPTION, AES_CFB1, output_data);
  endfunction

  /*
   * Function: encrypt_cfb8
   *
   * Description: User function for CFB Encryption with 8 bit offset
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   */
  function void encrypt_cfb8(
      input  byte unsigned state[],
      input  int unsigned  state_size,
      output byte unsigned output_data[]
    );

    xcrypt_cfb(state, state_size, AES_ENCRYPTION, AES_CFB8, output_data);
  endfunction

  /*
   * Function: decrypt_cfb8
   *
   * Description: User function for CFB Decryption with 8 bit offset
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   */
  function void decrypt_cfb8(
      input  byte unsigned state[],
      input  int unsigned  state_size,
      output byte unsigned output_data[]
    );

    xcrypt_cfb(state, state_size, AES_DECRYPTION, AES_CFB8, output_data);
  endfunction

  /*
   * Function: encrypt_cfb128
   *
   * Description: User function for CFB Encryption with 128 bit offset
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   */
  function void encrypt_cfb128(
      input  byte unsigned state[],
      input  int unsigned  state_size,
      output byte unsigned output_data[]
    );

    xcrypt_cfb(state, state_size, AES_ENCRYPTION, AES_CFB128, output_data);
  endfunction

  /*
   * Function: decrypt_cfb128
   *
   * Description: User function for CFB Decryption with 128 bit offset
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   */
  function void decrypt_cfb128(
      input  byte unsigned state[],
      input  int unsigned  state_size,
      output byte unsigned output_data[]
    );

    xcrypt_cfb(state, state_size, AES_DECRYPTION, AES_CFB128, output_data);
  endfunction

  /*
   * Function: aes_main
   *
   * Description: User main utilitary function for selecting all modes
   *
   * Parameters:
   *  state - input data for the encryption/decryption
   *  output_data - the resulting output
   *  operation - either AES_ENCRYPTION or AES_DECRYPTION
   *  block_mode - AES_ECB, AES_CTR, AES_CBC, AES_OFB, AES_CFB1, AES_CFB8 or AES_CFB128
   */
  function void aes_main(
      input  byte unsigned              state[],
      input  int unsigned               state_size,
      input  amiq_aes_encrypt_decrypt_e operation,
      input  amiq_aes_block_mode_e      block_mode,
      output byte unsigned              output_data[],
      input  byte unsigned              missing_bits_in_last_byte = 0
    );
    case (block_mode)
      AES_ECB : begin
        xcrypt_ecb(state, state_size, operation, output_data, missing_bits_in_last_byte);
      end
      AES_CTR : begin
        xcrypt_ctr(state, state_size, operation, output_data);
      end
      AES_CBC : begin
        xcrypt_cbc(state, state_size, operation, output_data, missing_bits_in_last_byte);
      end
      AES_OFB : begin
        xcrypt_ofb(state, state_size, operation, output_data, missing_bits_in_last_byte);
      end
      AES_CFB1, AES_CFB8, AES_CFB128 : begin
        xcrypt_cfb(state, state_size, operation, block_mode, output_data);
      end
      default: begin
        `uvm_error(this.get_full_name(), "Undefined state!")
      end
    endcase;
  endfunction

endclass

`endif
