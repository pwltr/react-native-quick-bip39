type Wordlists = {
	[key: string]: string[];
};

import chinese_simplified from "./chinese_simplified.json";
import chinese_traditional from "./chinese_traditional.json";
import czech from "./czech.json";
import english from "./english.json";
import french from "./french.json";
import italian from "./italian.json";
import japanese from "./japanese.json";
import korean from "./korean.json";
import portuguese from "./portuguese.json";
import spanish from "./spanish.json";

const wordlists: Wordlists = {
	czech,
	english,
	spanish,
	french,
	italian,
	japanese,
	korean,
	portuguese,
	chinese_simplified,
	chinese_traditional,
};

export default wordlists;
