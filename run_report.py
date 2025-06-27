import subprocess
from pathlib import Path
from html import escape

OUTPUT_TXT = "system_enumeration.txt"
OUTPUT_HTML = "system_report.html"
SCRIPT_PATH = "./enumeration_script.sh"

def run_system_info():
    print("[*] Running system_info.sh...")
    result = subprocess.run(["bash", SCRIPT_PATH], capture_output=True, text=True)
    if result.returncode != 0:
        print("[-] Failed to run system_info.sh")
        print(result.stderr)
    else:
        print("[+] Script executed successfully.")

def parse_report(file_path):
    content = Path(file_path).read_text(errors='ignore')
    sections = []
    current_header = None
    current_subheader = None
    buffer = []

    for line in content.splitlines():
        if line.startswith("====="):
            if current_header:
                sections.append((current_header, current_subheader, buffer))
            current_header = line.strip("= \n")
            current_subheader = None
            buffer = []
        elif line.startswith("-- "):
            if current_subheader or buffer:
                sections.append((current_header, current_subheader, buffer))
            current_subheader = line.strip("- \n")
            buffer = []
        else:
            buffer.append(line)

    if current_header:
        sections.append((current_header, current_subheader, buffer))

    return sections

def build_html(sections):
    html_sections = ""
    headers = []
    last_header = None

    for header, subheader, lines in sections:
        block = "\n".join(lines).strip()
        if not block:
            continue

        header_attr = escape(header.lower())
        content_class = "content hidden" if len(lines) > 40 else "content"

        if header not in headers:
            headers.append(header)

        if last_header != header:
            if last_header is not None:
                html_sections += '</div>\n'
            html_sections += f'<div class="section-block" data-header-block="{header_attr}">\n<h2>{escape(header)}</h2>\n'
            last_header = header

        html_sections += f'''
        <div class="section" data-header="{header_attr}">
            {'<h3 class="subheading-toggle">' + escape(subheader) + '</h3>' if subheader else ''}
            <div class="{content_class}"><pre><code>{escape(block)}</code></pre></div>
        </div>
        '''

    html_sections += '</div>\n'
    return html_sections, headers

def write_html(content_blocks, headers):
    header_options = '\n'.join(f'<option value="{escape(h.lower())}">{escape(h)}</option>' for h in headers)

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>System Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; padding: 20px; }}
        h2 {{ border-bottom: 2px solid #ccc; margin-top: 30px; }}
        h3 {{ margin: 10px 0; color: #333; cursor: pointer; }}
        .content {{
            padding: 10px;
            border: 1px solid #ccc;
            background-color: #f4f4f4;
        }}
        .hidden {{ display: none; }}
        pre {{ overflow-x: auto; }}
        .filter-bar {{
            margin-bottom: 20px;
            padding: 10px;
            background: #eee;
            border: 1px solid #ccc;
        }}
        .filter-bar label {{
            margin-right: 10px;
            font-weight: bold;
        }}
    </style>
    <script>
        function filterContent() {{
            const headerValue = document.getElementById('headerFilter').value.toLowerCase();
            const searchValue = document.getElementById('searchBox').value.toLowerCase();

            document.querySelectorAll('.section-block').forEach(block => {{
                const blockHeader = block.getAttribute('data-header-block');
                const matchesHeader = (headerValue === 'all' || blockHeader === headerValue);

                if (matchesHeader) {{
                    block.style.display = '';
                    block.querySelectorAll('.section').forEach(section => {{
                        const text = section.innerText.toLowerCase();
                        const matchesSearch = searchValue === '' || text.includes(searchValue);
                        section.style.display = matchesSearch ? '' : 'none';
                    }});
                }} else {{
                    block.style.display = 'none';
                }}
            }});
        }}

        document.addEventListener('DOMContentLoaded', function () {{
            document.querySelectorAll('.subheading-toggle').forEach(h3 => {{
                h3.addEventListener('click', () => {{
                    const content = h3.nextElementSibling;
                    if (content) {{
                        content.classList.toggle('hidden');
                    }}
                }});
            }});
        }});
    </script>
</head>
<body>
    <h1>Linux System Report</h1>
    <p style="background: #fff3cd; border: 1px solid #ffeeba; padding: 10px; color: #856404;">
    ⚠️ Some findings are collapsed because they use too much space on the screen. Click on the subheading when you want to expand the resultss.
</p>
    <div class="filter-bar">
        <label for="headerFilter">Header:</label>
        <select id="headerFilter" onchange="filterContent()">
            <option value="all">All</option>
            {header_options}
        </select>
        <label for="searchBox">Search:</label>
        <input type="text" id="searchBox" onkeyup="filterContent()" placeholder="Search content..." />
    </div>

    {content_blocks}
</body>
</html>
    """
    Path(OUTPUT_HTML).write_text(html)
    print(f"[+] HTML report saved to {OUTPUT_HTML}")

def main():
    run_system_info()
    sections = parse_report(OUTPUT_TXT)
    html_sections, headers = build_html(sections)
    write_html(html_sections, headers)

if __name__ == "__main__":
    main()
