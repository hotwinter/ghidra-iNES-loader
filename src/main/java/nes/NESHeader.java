package nes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class NESHeader implements StructConverter {
	private byte[] magic;
	private int prg_rom_size_16k;
	private int chr_rom_size_8k;
	private int rom_control_flag_0;
	private int rom_control_flag_1;
	private int ram_size_8k;
	private byte[] reserved;
	
	public NESHeader(BinaryReader reader) throws IOException {
		magic = reader.readNextByteArray(NESConstants.NES_MAGIC.length());
		if (!NESConstants.NES_MAGIC.equals(new String(magic))) {
			throw new IOException("not an NES file.");
		}
		prg_rom_size_16k = reader.readNextUnsignedByte();
		if (prg_rom_size_16k > NESConstants.MAX_PRG_ROM_BANKS) {
			throw new IOException("PRG ROM too big");
		}
		chr_rom_size_8k = reader.readNextUnsignedByte();
		if (chr_rom_size_8k > NESConstants.MAX_CHR_ROM_BANKS) {
			throw new IOException("CHR ROM too big");
		}
		rom_control_flag_0 = reader.readNextUnsignedByte();
		rom_control_flag_1 = reader.readNextUnsignedByte();
		int mapper = getMapper();
		if (!isSupported(mapper)) {
			throw new IOException("Mapper " + mapper + " not supported");
		}
		ram_size_8k = reader.readNextUnsignedByte();
		reserved = reader.readNextByteArray(7);
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("header_item", 0);
		structure.add(STRING, 4, "magic", null);
		structure.add(BYTE, 1, "prg_rom_size_16k", null);
		structure.add(BYTE, 1, "chr_rom_size_16k", null);
		structure.add(BYTE, 1, "rom_control_flag_0", null);
		structure.add(BYTE, 1, "rom_control_flag_1", null);
		structure.add(BYTE, 1, "ram_size_8k", null);
		structure.add(BYTE, 7, "reserved", null);
		return structure;
		
	}
	
	public String getMagic() {
		return new String(magic);
	}
	
	public int getPrgRomBase() {
		return NESConstants.HEADER_SIZE;
	}
	
	public int getChrRomBase() {
		return NESConstants.HEADER_SIZE + getPrgRomSize();
	}
	
	public int getPrgRomSize() {
		return prg_rom_size_16k * NESConstants.PRG_ROM_BANK_SIZE;
	}
	
	public int getChrRomSize() {
		return chr_rom_size_8k * NESConstants.CHR_ROM_BANK_SIZE;
	}
	
	public int getMapper() {
		return (rom_control_flag_1 & 0xf0) | ((rom_control_flag_0 >> 4) & 0xf);
	}
	
	private boolean isSupported(int mapper) {
		for (int i : NESConstants.SUPPORTED_MAPPERS) {
			if (mapper == i) {
				return true;
			}
		}
		return false;
	}
}
