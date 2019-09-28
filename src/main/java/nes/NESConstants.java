package nes;

public final class NESConstants {
	public static final String NES_MAGIC = new String(new byte[] {0x4e, 0x45, 0x53, 0x1a}); 
	public static final int HEADER_SIZE = 0x10;
	public static final int KB = 0x400;
	public static final int RAM_START_ADDRESS = 0x0;
	public static final int RAM_SIZE = 0x2000;

	public static final int IOREGS_START_ADDRESS = 0x2000;
	public static final int IOREGS_SIZE = 0x2020;

	public static final int EXPROM_START_ADDRESS = 0x4020;
	public static final int EXPROM_SIZE = 0x1FE0;

	public static final int SRAM_START_ADDRESS = 0x6000;
	public static final int SRAM_SIZE = 0x2000;

	// start address and size of a trainer, if present
	public static final int TRAINER_START_ADDRESS = 0x7000;
	public static final int TRAINER_SIZE = 0x0200;

	public static int ROM_START_ADDRESS = 0x8000;
	public static int ROM_SIZE = 0x8000;

	public static int PRG_PAGE_SIZE = 16 * KB;
	public static int CHR_PAGE_SIZE = 8 * KB;


	public static int PRG_ROM_BANK_SIZE = PRG_PAGE_SIZE;
	public static int PRG_ROM_8K_BANK_SIZE = 0x2000;
	public static int MAX_PRG_ROM_BANKS = ROM_SIZE / PRG_ROM_BANK_SIZE;
	public static int PRG_ROM_BANK_LOW_ADDRESS = ROM_START_ADDRESS;
	public static int PRG_ROM_BANK_HIGH_ADDRESS = PRG_ROM_BANK_LOW_ADDRESS + PRG_ROM_BANK_SIZE;
	public static int PRG_ROM_BANK_8000 = 0x8000;
	public static int PRG_ROM_BANK_A000 = 0xA000;
	public static int PRG_ROM_BANK_C000 = 0xC000;
	public static int PRG_ROM_BANK_E000 = 0xE000;


	public static int CHR_ROM_BANK_SIZE = CHR_PAGE_SIZE;
	public static final int MAX_CHR_ROM_BANKS = 2;
	public static int CHR_ROM_BANK_ADDRESS = RAM_START_ADDRESS;

	// start address of vectors
	public static int NMI_VECTOR_START_ADDRESS = 0xFFFA;
	public static int RESET_VECTOR_START_ADDRESS = 0xFFFC;
	public static int IRQ_VECTOR_START_ADDRESS = 0xFFFE;
	
	public static int[] SUPPORTED_MAPPERS = {NESMappers.NO_MAPPER};
}
