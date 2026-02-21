package com.hideakin.util;

public class CommandLineIterator {

	private final String[] _args;
	private int _index = 0;

	public CommandLineIterator(String[] args) {
		_args = args;
	}

	public boolean hasNext() {
		return _index < _args.length;
	}

	public String next() {
		return _index < _args.length ? _args[_index++] : null;
	}

	public int nextInteger() {
		try {
			return Integer.parseInt(next());
		} catch (NumberFormatException e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public byte[] nextBinary() {
		return HexString.parse(next());
	}

	public String peek(int position) {
		int index = _index + position;
		return 0 <= index && index < _args.length ? _args[index] : null;
	}

}
