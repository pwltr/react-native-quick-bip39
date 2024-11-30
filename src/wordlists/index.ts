type Wordlists = {
    [key: string]: string[];
};

import czech from "./czech.json";
import english from "./english.json";
import spanish from "./spanish.json";
import french from "./french.json";
import italian from "./italian.json";
import japanese from "./japanese.json";
import korean from "./korean.json";
import portuguese from "./portuguese.json";
import chinese_simplified from "./chinese_simplified.json";
import chinese_traditional from "./chinese_traditional.json";

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