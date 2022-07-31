# import third party libraries
from markdown import preprocessors, extensions, Markdown

# import local python libraries
from .Constants import CONSTANTS

# import python standard libraries
import re
from dataclasses import dataclass

@dataclass(frozen=True, repr=False)
class UsefulRegexForMarkdown:
    """This class will be used to store the regex pattern for Markdown syntax and HTML tags."""
    MARKDOWN_ANCHOR_REGEX: re.Pattern[str] = re.compile(r"\[(.*?)\]\((.*?)\)")
    HTML_ANCHOR_REGEX: re.Pattern[str] = re.compile(r"(&lt;a.*?)(href=)(&#x27;|&quot;)(.*?)(&#x27;|&quot;)(.*?)(&gt;)(.*?)(&lt;/a&gt;)")

class AnchorTagPreprocessor(preprocessors.Preprocessor):
    """Add attributes to the anchor html tag or the anchor markdown syntax."""
    def run(self, lines:list) -> list:
        newLines = []
        for line in lines:
            htmlAnchorTagArray = UsefulRegexForMarkdown.HTML_ANCHOR_REGEX.findall(line)
            if (len(htmlAnchorTagArray) > 0):
                for htmlAnchorTag in htmlAnchorTagArray:
                    line = line.replace(
                        "".join(htmlAnchorTag),
                        fr"<a rel='nofollow' target='_blank' href='{CONSTANTS.REDIRECT_CONFIRMATION_URL}?{CONSTANTS.REDIRECT_CONFIRMATION_PARAM_NAME}={htmlAnchorTag[3]}'>{htmlAnchorTag[-2]}</a>"
                    )

            markdownAnchorTagArray = UsefulRegexForMarkdown.MARKDOWN_ANCHOR_REGEX.findall(line)
            if (len(markdownAnchorTagArray) > 0):
                for markdownAnchorTag in markdownAnchorTagArray:
                    hrefURL = markdownAnchorTag[1]
                    line = re.sub(
                        pattern=UsefulRegexForMarkdown.MARKDOWN_ANCHOR_REGEX,
                        repl=fr"<a rel='nofollow' target='_blank' href='{CONSTANTS.REDIRECT_CONFIRMATION_URL}?{CONSTANTS.REDIRECT_CONFIRMATION_PARAM_NAME}={hrefURL}'>\1</a>",
                        string=line,
                        count=1 # max number of pattern occurrences before replacement
                    )

            newLines.append(line)
        return newLines

class AnchorTagExtension(extensions.Extension):
    """Will add rel="nofollow" before markdown conversion for HTML tags or markdown syntax."""
    def extendMarkdown(self, md:Markdown) -> None:
        md.registerExtension(self)
        # Note that the integer in the third argument is the priority when parsing the markdown string.
        md.preprocessors.register(AnchorTagPreprocessor(md), "addAttributesToAnchorTags", 75)

__all__ = [
    "AnchorTagExtension"
]