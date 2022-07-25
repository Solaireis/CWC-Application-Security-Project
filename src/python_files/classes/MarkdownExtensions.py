# import third party libraries
from dataclasses import dataclass
import markdown

# import python standard libraries
import re

@dataclass(frozen=True, repr=False)
class MarkdownRegex:
    """This class will be used to store the regex pattern for Markdown syntax."""
    ANCHOR_REGEX: re.Pattern[str] = re.compile(r"^\[(.*?)\]\((.*?)\)$")

class AnchorTagPreprocessor(markdown.preprocessors.Preprocessor):
    """Add attributes to the anchor html tag or the anchor markdown syntax."""
    def run(self, lines):
        newLines = []
        for line in lines:
            if (line.startswith("<a")):
                line = line.replace("<a", "<a rel='nofollow'")
            elif (re.fullmatch(MarkdownRegex.ANCHOR_REGEX, line)):
                line = re.sub(MarkdownRegex.ANCHOR_REGEX, r"<a rel='nofollow' href='\2'>\1</a>", line)
            newLines.append(line)
        return newLines

class AnchorTagExtension(markdown.extensions.Extension):
    """Will add rel="nofollow" before markdown conversion for HTML tags or markdown syntax."""
    def extendMarkdown(self, md):
        md.registerExtension(self)
        # Note that the integer in the third argument is the priority when parsing the markdown string.
        md.preprocessors.register(AnchorTagPreprocessor(md), "addAttributesToAnchorTags", 75)

__all__ = [
    "AnchorTagExtension"
]