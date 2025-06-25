import os
import time
import random
import re
import json

import requests
from PyQt5.QtWidgets import QInputDialog

import idaapi
import idautils
import idc
import ida_lines

PLUGIN_NAME = "AIMachDec"
ACTION_NAME = f"{PLUGIN_NAME}:run"
HOTKEY = "Ctrl-Shift-A"

def ask_option(title, options):
    item, ok = QInputDialog.getItem(None, title, "Select:", options, 0, False)
    if ok and item:
        return options.index(item)
    return -1

class PopupHook(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
            popup.add_action(ACTION_NAME, None)

class AIProvider:
    def __init__(self, prompt, model, api_key_env, url, headers_fn, payload_fn):
        self.prompt = prompt
        self.model = model
        self.api_key_env = api_key_env
        self.api_key = os.getenv(api_key_env)
        self.url = url
        self.headers_fn = headers_fn
        self.payload_fn = payload_fn

    def chat(self):
        if self.api_key_env and not self.api_key:
            idaapi.msg(f"[AIMachDec] Missing API key: {self.api_key_env}\n")
            idaapi.msg(f"[AIMachDec] Set it in the IDA python console like this:\n")
            idaapi.msg(f"  import os\n")
            idaapi.msg(f"  os.environ[\"{self.api_key_env}\"] = \"<api_key>\"\n")
            raise ValueError(f"API key '{self.api_key_env}' not found in environment variables.")

        headers = self.headers_fn(self.api_key)
        payload = self.payload_fn(self.prompt, self.model)
        response = requests.post(self.url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        data = response.json()
        return clean_response(data)

def get_prompt(content, lang):
    lc_content = content.lower()
    if lang == 'auto':
        if any(x in lc_content for x in ('objc_msgsend', '_objc_', 'selector', 'nsobject', '@interface', '@implementation', 'nsstring')):
            lang = 'Objective-C'
        elif any(x in lc_content for x in ('swift_', 'metadata accessor for', '.swift', '_stdlib_', '_assertionfailure', 'swift_getinitializedobjcclass')):
            lang = 'Swift'
        else:
            lang = 'C'
    return PROMPT_TEMPLATE.format(language=lang.capitalize()) % content, lang.lower()

def clean_response(data):
    content = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
    match = re.search(r"```(?:[a-zA-Z0-9_+-]*\n)?(.*?)\n?```", content, re.DOTALL)
    return match.group(1).strip() if match else content

PROMPT_TEMPLATE = '''
You are an expert reverse engineer specializing in AARCH64/ARM64 assembly on the Apple platform.
Analyze the following AARCH64/ARM64 assembly function and provide its equivalent {language} pseudo-code.
Focus on accuracy, readability, and standard {language} conventions.
Respond ONLY with the {language} code block. Do not include explanations, markdown formatting, or any text outside the code.
Simplify logic where possible (e.g., convert complex addressing modes or bitwise operations into clearer {language} expressions).
Use descriptive variable and function names based on context, if possible.
If the assembly includes standard library calls (heuristically identifiable), represent them with appropriate {language} function calls.
Handle common AARCH64/ARM64 patterns like function prologues/epilogues correctly (e.g., setting up/tearing down stack frames).
Convert assembly control flow (branches, conditional branches) into {language} control flow (if/else, loops, goto if necessary but prefer structured flow).
If string literals or constants are clearly loaded into registers (e.g., from comments like '; "STRING"' or immediate loads), use them in the {language} code.
Assembly:

%s'''

def openai_headers(api_key):
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

def openai_payload(prompt, model):
    return {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "top_p": 1.0
    }

PROVIDER_MAP = {
    "OpenAI GPT-4": ("openai", "gpt-4", "OPENAI_API_KEY", "https://api.openai.com/v1/chat/completions", openai_headers, openai_payload),
    "Claude 3 Opus": ("claude", "claude-3-opus-20240229", "ANTHROPIC_API_KEY", "https://api.anthropic.com/v1/messages",
             lambda key: {"x-api-key": key, "content-type": "application/json"},
             lambda prompt, model: {
                 "model": model,
                 "messages": [{"role": "user", "content": prompt}],
                 "max_tokens": 1024,
                 "temperature": 0.2,
                 "top_p": 1.0
             }),
    "Ollama LLaMA 3": ("ollama", "llama3", "", "http://localhost:11434/api/chat",
             lambda _: {"Content-Type": "application/json"},
             lambda prompt, model: {
                 "model": model,
                 "messages": [
                     {"role": "system", "content": "Provide very brief, concise responses"},
                     {"role": "user", "content": prompt}
                 ],
                 "stream": False
             }),
    "Perplexity Sonar": ("sonar", "sonar", "PERPLEXITY_API_KEY", "https://api.perplexity.ai/chat/completions",
             lambda key: {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
             lambda prompt, model: {
                 "model": model,
                 "messages": [
                     {"role": "system", "content": "Be precise and concise."},
                     {"role": "user", "content": prompt}
                 ],
                 "temperature": 0.2,
                 "top_p": 1.0
             }),
    "OpenRouter DeepCoder 14B (free)": ("openrouter", "agentica-org/deepcoder-14b-preview:free", "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1/chat/completions",
             lambda key: {
                 "Authorization": f"Bearer {key}",
                 "Content-Type": "application/json",
                 "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", ""),
                 "X-Title": os.getenv("OPENROUTER_SITE_NAME", "")
             },
             lambda prompt, model: {
                 "model": model,
                 "messages": [{"role": "user", "content": prompt}],
                 "temperature": 0.2,
                 "top_p": 1.0
             })
}

LANGUAGE_MAP = {
    "C": "c",
    "Objective-C": "objc",
    "Swift": "swift",
    "Auto-detect": "auto"
}

class AIAsmSelector(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "AI-assisted pseudo-code from assembly"
    help = "Select AI and language to translate AARCH64 asm to pseudo-code"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = HOTKEY

    def init(self):
        desc = idaapi.action_desc_t(
            ACTION_NAME, f"Run {PLUGIN_NAME}",
            self.ActionHandler(), HOTKEY, f"Run {PLUGIN_NAME}", -1
        )
        idaapi.register_action(desc)
        self.hook = PopupHook()
        self.hook.hook()
        return idaapi.PLUGIN_OK

    class ActionHandler(idaapi.action_handler_t):
        def activate(self, ctx):
            AIAsmSelector().run(None)
            return 1
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    def run(self, arg):
        opt1 = ask_option("Select AI Provider", list(PROVIDER_MAP.keys()))
        if opt1 < 0:
            return
        opt2 = ask_option("Select Language", list(LANGUAGE_MAP.keys()))
        if opt2 < 0:
            return
        sel1 = list(PROVIDER_MAP.keys())[opt1]
        sel2 = list(LANGUAGE_MAP.keys())[opt2]

        viewer = idaapi.get_current_viewer()
        if not viewer:
            idaapi.msg(f"[{PLUGIN_NAME}] No viewer found\n")
            return
        try:
            ea = idaapi.get_viewer_ea(viewer)
        except AttributeError:
            ea = idc.get_screen_ea()
        func = idaapi.get_func(ea)
        if not func:
            idaapi.msg(f"[{PLUGIN_NAME}] No function selected\n")
            return

        start = func.start_ea
        end = func.end_ea
        asm_lines = []
        ea = start
        while ea < end:
            line = ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_FORCE_CODE)
            if line:
                asm_lines.append(line.strip())
            ea = idc.next_head(ea, end)
        asm_code = "\n".join(asm_lines)

        prompt_text, _ = get_prompt(asm_code, LANGUAGE_MAP[sel2])
        provider_id, model, api_key_env, url, headers_fn, payload_fn = PROVIDER_MAP[sel1]
        provider = AIProvider(prompt_text, model, api_key_env, url, headers_fn, payload_fn)
        try:
            pseudo_code = provider.chat()
        except Exception as e:
            idaapi.msg(f"[{PLUGIN_NAME}] AI call failed: {e}\n")
            return

        final_code = ["// Decompiled output", pseudo_code, ""]
        
        title_base = "AI Pseudocode"
        index = 0
        while idaapi.find_widget(f"{title_base}-{chr(65 + index)}"):
            index += 1
            if index >= 26:
                idaapi.msg(f"[{PLUGIN_NAME}] Too many open pseudocode viewers\n")
                return
        title = f"{title_base}-{chr(65 + index)}"
        cv = idaapi.simplecustviewer_t()
        if not cv.Create(title):
            idaapi.msg(f"[{PLUGIN_NAME}] Failed to create viewer\n")
            return

        
        for line in final_code:
            for subline in line.splitlines():
                cv.AddLine(subline)
        cv.Show()

    def term(self):
        idaapi.unregister_action(ACTION_NAME)
        self.hook.unhook()

def PLUGIN_ENTRY():
    return AIAsmSelector()