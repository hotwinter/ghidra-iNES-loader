/* ###
j * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nes;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class NESLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "NES";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader reader = new BinaryReader(provider, true);
		NESHeader header = new NESHeader(reader);
		loadSpecs.add(new LoadSpec(this, 0,
			new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));
		return loadSpecs;
	}

	private void setInitAddr(byte[] data, int addr, int value) {
		// Assuming little endian
		addr = addr - NESConstants.ROM_START_ADDRESS;
		if (addr + 1 < data.length) {
			data[addr] = (byte) (value & 0xff);
			data[addr + 1] = (byte) (value >> 8);
		}
	}
	
	// Duplicate data from src to dest, until the end of dest
	private byte[] duplicate(byte[] src, int size, int bs) {
		// We are doing bank copies here
		if (size == src.length) {
			return src;
		}
		assert(size % bs == 0 && src.length % bs == 0 && size >= src.length);
		byte[] dest = new byte[size];
		int banks = size / bs;
		for (int i = 0; i < banks; i++) {
			System.arraycopy(src, (i * bs) % src.length, dest, i * bs, bs);
		}
		return dest;
	}
	
	private int getShortLE(byte[] src, int off) {
		off = off - NESConstants.ROM_START_ADDRESS;
		assert(off + 1 < src.length);
		return (src[off] | (src[off + 1] << 8)) & 0xffff;
	}
	
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		monitor.setMessage(getName() + "Loader: Start loading");
		BinaryReader reader = new BinaryReader(provider, true);
		NESHeader header = new NESHeader(reader);
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		
		try {
			byte[] read_prgrom = reader.readNextByteArray(header.getPrgRomSize());

			int mapper = header.getMapper();
			switch (mapper) {
				case NESMappers.NO_MAPPER:
					// fill with zeros
					byte[] prgrom = duplicate(read_prgrom, NESConstants.ROM_SIZE, NESConstants.PRG_ROM_BANK_SIZE);
					api.createMemoryBlock("PRGROM", api.toAddr(NESConstants.ROM_START_ADDRESS), prgrom, false);
					
					Address reset = api.toAddr(getShortLE(prgrom, NESConstants.RESET_VECTOR_START_ADDRESS));
					api.addEntryPoint(reset);
					api.createFunction(reset, "_RESET");
					
					int nmiAddr = getShortLE(prgrom, NESConstants.NMI_VECTOR_START_ADDRESS);
					if (nmiAddr != 0) {
						api.createFunction(api.toAddr(nmiAddr), "_NMI");
					}

					int irqAddr = getShortLE(prgrom, NESConstants.IRQ_VECTOR_START_ADDRESS);
					if (irqAddr != 0) {
						api.createFunction(api.toAddr(irqAddr), "_IRQ");
					}
					// Seems like the CHR rom is not used in the CPU? so we are done...?
					break;
				default:
					throw new Exception("Mapper " + mapper + " not implemented");
			}
		} catch (Exception e) {
			Msg.showError(this, null, getName() + "Loader", e.getMessage(), e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {
		return super.validateOptions(provider, loadSpec, options);
	}
}
