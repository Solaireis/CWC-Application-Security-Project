# import third party libraries
import markdown

# import python standard libraries
import re

# Add attributes to anchor tag in the markdown string
class AnchorTagPreprocessor(markdown.preprocessors.Preprocessor):
    def run(self, lines):
        newLines = []
        for line in lines:
            if (line.startswith("<a")):
                line = line.replace("<a", "<a rel=\"nofollow\"")
            newLines.append(line)
        return newLines

class AnchorTagPreExtension(markdown.extensions.Extension):
    """
    Will add rel="nofollow" after markdown conversion for <a ..>text</a> HTML tags.
    """
    def extendMarkdown(self, md, md_globals):
        md.registerExtension(self)
        # Note that the integer in the third argument is the priority when parsing the markdown string.
        md.preprocessors.register(AnchorTagPreprocessor(md), "addAttributesToAnchorTags", 75)

# Convert markdown (anchorText)[anchorLink] and add rel="nofollow" after markdown conversion.
class AnchorTagPostprocessor(markdown.postprocessors.Postprocessor):
    def run(self, text):
        mdAnchorRegex = re.compile(r"""
            \((.*?)\) # Matches (anchorText)
            \[(.*?)\] # Matches [anchorLink]
        """, re.VERBOSE)
        return re.sub(mdAnchorRegex, r"<a href='\1' rel='nofollow'>\2</a>", text)

class AnchorTagPostExtension(markdown.extensions.Extension):
    """
    Will add rel="nofollow" after markdown conversion for (anchorText)[anchorLink] markdown syntax.
    """
    def extendMarkdown(self, md, md_globals):
        md.registerExtension(self)
        # Note that the integer in the third argument is the priority when parsing the markdown string.
        md.postprocessors.register(AnchorTagPostprocessor(md), "addAttributesToAnchorMarkdownTags", 75)

__all__ = [
    "AnchorTagPreExtension",
    "AnchorTagPostExtension"
]