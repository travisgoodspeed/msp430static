#ifndef __JTAG_NOOP__
#define __JTAG_NOOP__

#define DEFAULT_JTAG_TDO_BIT_MASK           (1 << 0)
#define DEFAULT_JTAG_TDI_BIT_MASK           (1 << 1)
#define DEFAULT_JTAG_TMS_BIT_MASK           (1 << 2)
#define DEFAULT_JTAG_TCK_BIT_MASK           (1 << 3)

#define IR_CNTRL_SIG_16BIT          0x13
#define IR_CNTRL_SIG_CAPTURE        0x14
#define IR_CNTRL_SIG_RELEASE        0x15
#define IR_PREPARE_BLOW             0x22
#define IR_EX_BLOW                  0x24
#define IR_DATA_16BIT               0x41
#define IR_DATA_CAPTURE             0x42
#define IR_DATA_QUICK               0x43
#define IR_DATA_PSA                 0x44
#define IR_SHIFT_OUT_PSA            0x46
#define IR_ADDR_16BIT               0x83
#define IR_ADDR_CAPTURE             0x84
#define IR_DATA_TO_ADDR             0x85
#define IR_BYPASS                   0xFF

extern int jtag_tdo_bit_mask;
extern int jtag_tdi_bit_mask;
extern int jtag_tms_bit_mask;
extern int jtag_tck_bit_mask;

typedef enum
{
    JTAG_STATE_TEST_LOGIC_RESET = 0x00,
    JTAG_STATE_RUN_TEST_IDLE,
    JTAG_STATE_SELECT_DR_SCAN,
    JTAG_STATE_CAPTURE_DR,
    JTAG_STATE_SHIFT_DR,
    JTAG_STATE_EXIT1_DR,
    JTAG_STATE_PAUSE_DR,
    JTAG_STATE_EXIT2_DR,
    JTAG_STATE_UPDATE_DR,
    JTAG_STATE_SELECT_IR_SCAN,
    JTAG_STATE_CAPTURE_IR,
    JTAG_STATE_SHIFT_IR,
    JTAG_STATE_EXIT1_IR,
    JTAG_STATE_PAUSE_IR,
    JTAG_STATE_EXIT2_IR,
    JTAG_STATE_UPDATE_IR,
} JTAG_STATE;

typedef struct __IR_NAME
{
    char *ir_name;
    int   ir_value;
} IR_NAME;

// DEBUG ONLY!!!
static inline int break_here(void)
{
    return 3;
}

static inline int jtag_tdo_bit(int entry)
{
    return (entry & jtag_tdo_bit_mask) ? 1 : 0;
}

static inline int jtag_tdi_bit(int entry)
{
    return (entry & jtag_tdi_bit_mask) ? 1 : 0;
}

static inline int jtag_tms_bit(int entry)
{
    return (entry & jtag_tms_bit_mask) ? 1 : 0;
}

static inline int jtag_tck_bit(int entry)
{
    return (entry & jtag_tck_bit_mask) ? 1 : 0;
}


#endif


