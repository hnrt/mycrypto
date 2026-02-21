package com.hideakin.util;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

public class CommandLineOptionSet {

	private final String _name;
	private final Map<String, CommandLineOption> _map = new LinkedHashMap<>();
	private final Map<String, String> _aliases = new LinkedHashMap<>();
	private String _format;
	private String _wrappingLine;

	public CommandLineOptionSet(String name) {
		_name = name;
	}

	public CommandLineOptionSet add(String key, Function<CommandLineIterator, Boolean> function) {
		_map.put(key, new CommandLineOption(key, null, null, function));
		return this;
	}

	public CommandLineOptionSet add(String key, String description, Function<CommandLineIterator, Boolean> function) {
		_map.put(key, new CommandLineOption(key, null, description, function));
		return this;
	}

	public CommandLineOptionSet add(String key, String operand, String description, Function<CommandLineIterator, Boolean> function) {
		_map.put(key, new CommandLineOption(key, operand, description, function));
		return this;
	}

	public CommandLineOptionSet addAlias(String alias, String key) {
		_aliases.put(alias, key);
		return this;
	}

	public boolean process(String[] args) {
		return process(new CommandLineIterator(args));
	}

	public boolean process(CommandLineIterator iterator) {
		while (iterator.hasNext()) {
			String key = iterator.next();
			CommandLineOption option = _map.get(key);
			if (option == null) {
				String key2 = _aliases.get(key);
				if (key2 != null) {
					if (key2.startsWith("@")) {
						key2 = key2.substring(1);
					}
					option = _map.get(key2);
				}
				if (option == null) {
					throw new RuntimeException("Bad syntax: " + key);
				}				
			}
			if (!option.apply(iterator)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder s = new StringBuilder();
		s.append(_name);
		s.append(":\n");
		for (CommandLineOption option : _map.values()) {
			if (option.description() == null) {
				continue;
			}
			String key = option.operand() == null ? option.key() : option.key() + " " + option.operand();
			s.append(String.format(_format, key, option.description().replaceAll("\n", _wrappingLine)));
		}
		for (Map.Entry<String, String> e : _aliases.entrySet()) {
			CommandLineOption option = _map.get(e.getValue());
			if (option == null || option.description() == null) {
				continue;
			}
			s.append(String.format(_format, e.getKey(), "is an alias of " + e.getValue()));
		}
		return s.toString();
	}

	private int measureKeyOperandLength(int separatorLength) {
		int length = 0;
		for (CommandLineOption option : _map.values()) {
			if (option.description() == null) {
				continue;
			}
			int n1 = option.key().length();
			int n2 = option.operand() == null ? 0 : option.operand().length();
			int n = n1 + separatorLength + n2;
			if (length < n) {
				length = n;
			}
		}
		for (Map.Entry<String, String> e : _aliases.entrySet()) {
			CommandLineOption option = _map.get(e.getValue());
			if (option == null) {
				throw new RuntimeException(String.format("%s ==> %s is not registered!", e.getKey(), e.getValue()));
			}
			if (option.description() == null) {
				continue;
			}
			int n = e.getKey().length();
			if (length < n) {
				length = n;
			}
		}
		return length;
	}

	private void setFormat(int keyOperandLength) {
		_format = String.format("  %%-%ds  %%s\n", keyOperandLength);
		_wrappingLine = "\n" + TextHelpers.whitespaces(keyOperandLength + 4); // newline followed by indentation
	}

	public static void alignFormat(CommandLineOptionSet... optionSets) {
		int length = 0;
		for (CommandLineOptionSet optionSet : optionSets) {
			int n = optionSet.measureKeyOperandLength(1);
			if (length < n) {
				length = n;
			}
		}
		for (CommandLineOptionSet optionSet : optionSets) {
			optionSet.setFormat(length);
		}
	}

}
