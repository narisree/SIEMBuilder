"""
Mermaid Renderer
Renders mermaid diagrams in Streamlit using HTML components.
"""

import re
import streamlit as st
import streamlit.components.v1 as components


def render_markdown_with_mermaid(markdown_content: str):
    """
    Render markdown content that may contain mermaid code blocks.
    Splits content at mermaid blocks and renders each part appropriately.
    
    Args:
        markdown_content: Markdown string potentially containing ```mermaid blocks
    """
    # Split on mermaid code blocks
    pattern = r'```mermaid\s*\n(.*?)```'
    parts = re.split(pattern, markdown_content, flags=re.DOTALL)
    
    # parts alternates: [text, mermaid_code, text, mermaid_code, ...]
    for i, part in enumerate(parts):
        if i % 2 == 0:
            # Regular markdown
            text = part.strip()
            if text:
                st.markdown(text, unsafe_allow_html=True)
        else:
            # Mermaid diagram code
            _render_mermaid(part.strip())


def _render_mermaid(mermaid_code: str, height: int = 400):
    """
    Render a single mermaid diagram using an HTML component.
    
    Args:
        mermaid_code: The mermaid diagram code (without the ```mermaid wrapper)
        height: Height of the rendered diagram in pixels
    """
    html = f"""
    <div style="background: white; padding: 10px; border-radius: 8px;">
        <pre class="mermaid">
{mermaid_code}
        </pre>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script>
        mermaid.initialize({{ startOnLoad: true, theme: 'default' }});
    </script>
    """
    components.html(html, height=height, scrolling=True)
