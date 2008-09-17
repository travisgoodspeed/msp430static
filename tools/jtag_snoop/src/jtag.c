#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <jtag_snoop.h>

char *ctrl_bits[] =
{
    "R/W",
    "UNDOC",
    "UNDOC",
    "HALT_JTAG",
    "BYTE",
    "UNDOC",
    "UNDOC",
    "INSTR_LOAD",
    "UNDOC",
    "TCE",
    "TCE1",
    "POR",
    "RLB",
    "TAGFUNCSAT",
    "SWITCH",
    "UNDOC"
};

IR_NAME ir_names[] =
{
    {"IR_CNTRL_SIG_16BIT",      IR_CNTRL_SIG_16BIT},
    {"IR_CNTRL_SIG_CAPTURE",    IR_CNTRL_SIG_CAPTURE},
    {"IR_CNTRL_SIG_RELEASE",    IR_CNTRL_SIG_RELEASE},
    {"IR_PREPARE_BLOW",         IR_PREPARE_BLOW},
    {"IR_EX_BLOW",              IR_EX_BLOW},
    {"IR_DATA_16BIT",           IR_DATA_16BIT},
    {"IR_DATA_CAPTURE",         IR_DATA_CAPTURE},
    {"IR_DATA_QUICK",           IR_DATA_QUICK},
    {"IR_DATA_PSA",             IR_DATA_PSA},
    {"IR_SHIFT_OUT_PSA",        IR_SHIFT_OUT_PSA},
    {"IR_ADDR_16BIT",           IR_ADDR_16BIT},
    {"IR_ADDR_CAPTURE",         IR_ADDR_CAPTURE},
    {"IR_DATA_TO_ADDR",         IR_DATA_TO_ADDR},
    {"IR_BYPASS",               IR_BYPASS},
};
    
char *jtag_entries;
JTAG_STATE jtag_present_state, jtag_next_state;

int jtag_tdo_bit_mask = DEFAULT_JTAG_TDO_BIT_MASK;
int jtag_tdi_bit_mask = DEFAULT_JTAG_TDI_BIT_MASK;
int jtag_tms_bit_mask = DEFAULT_JTAG_TMS_BIT_MASK;
int jtag_tck_bit_mask = DEFAULT_JTAG_TCK_BIT_MASK;

int current_offset = 0;

JTAG_STATE jtag_next_state_transitions[16][2] =
{
    {JTAG_STATE_RUN_TEST_IDLE, JTAG_STATE_TEST_LOGIC_RESET}, // TEST_LOGIC_RESET
    {JTAG_STATE_RUN_TEST_IDLE, JTAG_STATE_SELECT_DR_SCAN},   // RUN_TEST_IDLE
    {JTAG_STATE_CAPTURE_DR, JTAG_STATE_SELECT_IR_SCAN},      // SELECT_DR_SCAN
    {JTAG_STATE_SHIFT_DR, JTAG_STATE_EXIT1_DR},              // CAPTURE_DR
    {JTAG_STATE_SHIFT_DR, JTAG_STATE_EXIT1_DR},              // SHIFT_DR
    {JTAG_STATE_PAUSE_DR, JTAG_STATE_UPDATE_DR},             // EXIT1_DR
    {JTAG_STATE_PAUSE_DR, JTAG_STATE_EXIT2_DR},              // PAUSE_DR
    {JTAG_STATE_SHIFT_DR, JTAG_STATE_UPDATE_DR},             // EXIT2_DR
    {JTAG_STATE_RUN_TEST_IDLE, JTAG_STATE_SELECT_DR_SCAN},   // UPDATE_DR

    {JTAG_STATE_CAPTURE_IR, JTAG_STATE_TEST_LOGIC_RESET},    // SELECT_IR_SCAN
    {JTAG_STATE_SHIFT_IR, JTAG_STATE_EXIT1_IR},              // CAPTURE_IR
    {JTAG_STATE_SHIFT_IR, JTAG_STATE_EXIT1_IR},              // SHIFT_IR
    {JTAG_STATE_PAUSE_IR, JTAG_STATE_UPDATE_IR},             // EXIT1_IR
    {JTAG_STATE_PAUSE_IR, JTAG_STATE_EXIT2_IR},              // PAUSE_IR
    {JTAG_STATE_SHIFT_IR, JTAG_STATE_UPDATE_IR},             // EXIT2_IR
    {JTAG_STATE_RUN_TEST_IDLE, JTAG_STATE_SELECT_DR_SCAN},   // UPDATE_IR
};

int calculate_sum(char *line)
{
    int sum = 0, i;
    for (i = 0; i < 64; i++)
        sum += line[i] - '0';
    return sum;
}

void print_ir_name(int ir_contents)
{
    int i;
    printf("ir ");
    for (i = 0; i < sizeof(ir_names) / sizeof(IR_NAME); i++)
        if (ir_names[i].ir_value == ir_contents)
        {
            printf("%s\r\n", ir_names[i].ir_name);
            return;
        }    
    printf("0x%02X\r\n", ir_contents);
}

void print_dr_name(int ir_contents,
                   int tdi_shift_register,
                   int tdo_shift_register)
{
    int i;
    switch (ir_contents)
    {
    case IR_ADDR_16BIT:
        printf("dr out: 0x%05X, in: %05X\r\n",
               tdi_shift_register,
               tdo_shift_register);
        break;
    case 0x12:
        printf("dr out: 0x%02X, in: 0x%02X\r\n",
               tdi_shift_register,
               tdo_shift_register);
        break;
    case IR_CNTRL_SIG_CAPTURE:
        // Here we do the pretty printing of the bits of the control
        //  register.
        printf("dr out: 0x%04X, in: 0x%04X - ",
               tdi_shift_register,
               tdo_shift_register);
        for (i = 15; i >= 0; i--)
            if ((tdo_shift_register & (1 << i)) != 0)
                printf(":%s", ctrl_bits[i]);
        printf("\r\n");
        break;
    default:
        printf("dr out: 0x%04X, in: 0x%04X\r\n",
               tdi_shift_register,
               tdo_shift_register);
    }
}    

int seek_tck_rising_edge(int number_of_entries)
{
    int temp_current_offset = current_offset, this_tck_bit;
    // First look for a TCK LOW.
    do
    {
        temp_current_offset++;
        if (temp_current_offset == number_of_entries)
            return -1;
        this_tck_bit = jtag_tck_bit(jtag_entries[temp_current_offset]);   
    }
    while (this_tck_bit != 0);
        
    // Then look for a TCK HIGH.
    do
    {
        temp_current_offset++;
        if (temp_current_offset == number_of_entries)
            return -1;
        this_tck_bit = jtag_tck_bit(jtag_entries[temp_current_offset]);   
    }
    while (this_tck_bit == 0);
    return temp_current_offset;
}

int seek_tdi_toggling(int tdi_index, int tck_active, int number_of_entries)
{
    // This is the current tdi state.
    int tdi_bit = jtag_tdi_bit(jtag_entries[tdi_index]);
    
    // First look for a TCK LOW.
    int next_tdi_bit;
    do
    {
        tdi_index++;
        if (tdi_index == number_of_entries)
            return -1;
        next_tdi_bit = jtag_tdi_bit(jtag_entries[tdi_index]);
    }
    while ((next_tdi_bit == tdi_bit) && (tdi_index < tck_active));
    return tdi_index;
}

void usage(void)
{
    printf("Usage:\r\n");
    printf("    jtag -f filename [OPTION...]\r\n");
    printf("JTAG Options:\r\n");
    printf("    -o <arg>            Mask to use for TDO "
                "(default %d)\r\n", DEFAULT_JTAG_TDO_BIT_MASK);
    printf("    -i <arg>            Mask to use for TDI "
                "(default %d)\r\n", DEFAULT_JTAG_TDI_BIT_MASK);
    printf("    -k <arg>            Mask to use for TCK "
                "(default %d)\r\n", DEFAULT_JTAG_TCK_BIT_MASK);
    printf("    -m <arg>            Mask to use for TMS "
                "(default %d)\r\n", DEFAULT_JTAG_TMS_BIT_MASK);
    printf("    -s <arg>            Set startint state in the JTAG FSM "
                                            "(default Runt/Test-Idle)\r\n");
}

int main(int argc, char **argv)
{
    int ir_contents = 0, c;
    int number_of_entries, i;
    int tdo_shift_register, tdi_shift_register;
    int shift_xr_bit_count, tdo_pin_state, tdi_pin_state;
    char *fname = NULL;

    jtag_present_state = JTAG_STATE_RUN_TEST_IDLE;
    jtag_next_state = JTAG_STATE_SELECT_DR_SCAN;

    while ((c = getopt (argc, argv, "s:f:o:i:k:m:")) != -1)
        switch (c)
        {
        case 'f':
            fname = optarg;
            break;
        case 's':
            jtag_present_state = atoi(optarg);
            break;
        case 'o':
            jtag_tdo_bit_mask = atoi(optarg);
            break;
        case 'i':
            jtag_tdi_bit_mask = atoi(optarg);
            break;
        case 'k':
            jtag_tms_bit_mask = atoi(optarg);
            break;
        case 'm':
            jtag_tck_bit_mask = atoi(optarg);
            break;
        case '?':
            usage();
            return 1;
        default:
            abort ();
        }

    if (fname == NULL)
    {
        usage();
        return -1;
    }

    FILE *fp = fopen(fname, "r");
    if (fp == NULL)
    {
        printf("Cannot open %s file.\r\n", fname);
        return -1;
    }

    int ret = fscanf(fp, ";Size: %d", &number_of_entries);
    if (ret != 1)
    {
        printf("Unrecognized format.\n");
        return -1;
    }

    char line[32];
    // Discard the other lines.
    for (i = 1; i < 6; i++)
        fgets(line, sizeof(line), fp);
        
    // Now malloc the space required to hold all variables.
    jtag_entries = (char*)malloc(number_of_entries);
    if (jtag_entries == 0)
    {
        printf("Failed malloc()\n");
        return -1;
    }

    for (i = 0; i < number_of_entries; i++)
    {
        int tmp;
        fscanf(fp, "%08x", &tmp);
        jtag_entries[i] = tmp & 0x0F;
    }
    fclose(fp);
    
    // OK, now we can start analyzing the stream.
    while (jtag_present_state != -1)
    {
        int tck_active = seek_tck_rising_edge(number_of_entries);
        if (tck_active == -1)
            break;
        current_offset = tck_active;

        // Now we are ready to determine the next state based on the value of
        //  TMS; We sample the TMS 2 samples after the transition, to allow any
        //  possible glitch to settle.
        int32_t tms = jtag_tms_bit(jtag_entries[current_offset + 2]);
        jtag_next_state = jtag_next_state_transitions[jtag_present_state][tms]; 
                          
        // This is a pretty pedestrian way of implementing a state machine,
        //  but it works for now...
        switch (jtag_present_state)
        {
        case JTAG_STATE_RUN_TEST_IDLE:
            // In this state we need to trace any change of the state of
            //  TDI before any TCK toggling.
            // First, let's find out where the next TCK rising edge is going
            //  to happen.
            tck_active = seek_tck_rising_edge(number_of_entries);
            int tdi_toggle = current_offset;
            do
            {
                tdi_toggle = seek_tdi_toggling(tdi_toggle,
                                               tck_active,
                                               number_of_entries);
                if (tdi_toggle == -1)
                    return -1;
                if (tdi_toggle < tck_active)
                {
                    // We have a valid change of TDI.
                    // Print out the status of TDI after the transition.
                    int tdi = jtag_tdi_bit(jtag_entries[tdi_toggle]);
                    if (tdi == 1)
                        printf("SetTCLK\r\n");
                    else     
                        printf("ClrTCLK\r\n");
                }
            }        
            while (tdi_toggle < tck_active);
            break;        
        case JTAG_STATE_CAPTURE_DR:
            tdo_shift_register = 0;
            tdi_shift_register = 0;
            switch (ir_contents)
            {
            case IR_ADDR_16BIT:
                shift_xr_bit_count = 19;
                break;
            case 0x12:
                shift_xr_bit_count = 7;
                break;
            default:
                shift_xr_bit_count = 15;
            }    
            break;
        case JTAG_STATE_SHIFT_DR:
            // Again, we sample tdi and tdo 2 time slots after the transition
            //  to avoid glitches, as per Lichen's suggestion.
            tdi_pin_state = jtag_tdi_bit(jtag_entries[current_offset + 2]);
            tdo_pin_state = jtag_tdo_bit(jtag_entries[current_offset + 2]);
            tdi_shift_register |= tdi_pin_state << shift_xr_bit_count;
            tdo_shift_register |= tdo_pin_state << shift_xr_bit_count;
            shift_xr_bit_count--;
            break;
        case JTAG_STATE_UPDATE_DR:
            print_dr_name(ir_contents, tdi_shift_register, tdo_shift_register);
            break;
        case JTAG_STATE_CAPTURE_IR:
            tdo_shift_register = 0;
            tdi_shift_register = 0;
            shift_xr_bit_count = 0;
            break;
        case JTAG_STATE_SHIFT_IR:
            tdi_pin_state = jtag_tdi_bit(jtag_entries[current_offset + 1]);
            tdo_pin_state = jtag_tdo_bit(jtag_entries[current_offset + 1]);
            tdi_shift_register |= tdi_pin_state << shift_xr_bit_count;
            tdo_shift_register |= tdo_pin_state << shift_xr_bit_count;
            shift_xr_bit_count++;
            break;
        case JTAG_STATE_UPDATE_IR:
            ir_contents = tdi_shift_register;
            print_ir_name(ir_contents);
            if (ir_contents == IR_DATA_TO_ADDR)
                break_here();
            break;
        default:
            break;
        }
        jtag_present_state = jtag_next_state; 
    }

    return 0;
}
