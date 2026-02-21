package com.hideakin.util;

import java.util.function.Function;

public class CommandLineOption {

	private final String _key;
	private final String _operand;
	private final String _description;
	private final Function<CommandLineIterator, Boolean> _function;

	public CommandLineOption(String key, String operand, String description, Function<CommandLineIterator, Boolean> function) {
		_key = key;
		_operand = operand;
		_description = description;
		_function = function;
	}

	public String key() {
		return _key;
	}

	public String operand() {
		return _operand;
	}

	public String description() {
		return _description;
	}

	public Boolean apply(CommandLineIterator iterator) {
		return _function.apply(iterator);
	}

}
