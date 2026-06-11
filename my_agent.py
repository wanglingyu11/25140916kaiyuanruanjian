import os
import json
import re
import r2pipe
from zai import ZhipuAiClient

# ============================================================
# 我的智谱AI密钥
# ============================================================
ZHIPU_API_KEY = ""

# ============================================================
# 封装工具 - 使用 r2pipe
# ============================================================
def execute_r2_analysis(function_name):
    """使用r2pipe分析函数，返回汇编代码"""
    print(f"    [工具执行] r2分析函数: {function_name}")
    try:
        r2 = r2pipe.open("./challenge")
        r2.cmd("aaa")
        result = r2.cmd(f"pdf @ {function_name}")
        r2.quit()
        
        if not result or "Cannot find" in result or "not found" in result.lower():
            return f"[信息] 未找到函数 {function_name}，请尝试其他函数名"
        
        if len(result) > 4000:
            result = result[:4000] + "\n... (输出已截断)"
        return result
    except Exception as e:
        return f"[异常] r2pipe执行出错: {str(e)}"

def execute_ghidra_decompile(function_name):
    """使用r2pipe的Ghidra插件反编译函数"""
    print(f"    [工具执行] Ghidra反编译函数: {function_name}")
    try:
        r2 = r2pipe.open("./challenge")
        r2.cmd("aaa")
        result = r2.cmd(f"r2ghidra:decompile @ {function_name}")
        r2.quit()
        
        if not result or "Cannot find" in result:
            return f"[信息] 未找到函数 {function_name} 的反编译代码"
        
        if len(result) > 4000:
            result = result[:4000] + "\n... (输出已截断)"
        return result
    except Exception as e:
        return f"[异常] 反编译出错: {str(e)}"

def get_function_list():
    """获取程序中所有函数名"""
    try:
        r2 = r2pipe.open("./challenge")
        r2.cmd("aaa")
        result = r2.cmd("afl")
        r2.quit()
        
        # 解析函数名
        functions = []
        for line in result.split("\n"):
            parts = line.split()
            if len(parts) >= 3:
                func_name = parts[-1]
                if func_name and not func_name.startswith("0x"):
                    functions.append(func_name)
        return functions
    except Exception as e:
        print(f"获取函数列表失败: {e}")
        return ["main", "_start"]

# ============================================================
# 核心大脑：ReAct Agent
# ============================================================
def run_agent():
    print("\n" + "="*60)
    print("     ReAct Agent 静态分析实验 - 智谱AI版")
    print("="*60)

    # 获取函数列表
    print("\n正在获取函数列表...")
    functions = get_function_list()
    print(f"找到 {len(functions)} 个函数")
    
    # 构建函数列表字符串（限制数量，避免太长）
    func_list_str = "\n".join(functions[:20])  # 只取前20个
    if len(functions) > 20:
        func_list_str += f"\n... 共 {len(functions)} 个函数"

    # 构建系统提示词（注意：这里不是 f-string 的语法错误，是之前的问题）
    system_prompt = f"""
你是一位顶尖的二进制安全专家。现在你要分析一个名为 "challenge" 的 Linux 程序。

【可用的函数名】（从程序分析结果获得）：
{func_list_str}

【分析策略】：
1. 首先使用 run_r2_analysis 分析 main 函数
2. 然后使用 run_ghidra_decompile 反编译 main 和 fcn.00401216
3. 寻找危险函数：strcpy, gets, scanf, memcpy, sprintf 等
4. 注意：程序使用了 _strcpy_chk（安全版本），可能没有栈溢出

【输出格式】：
当你确定漏洞后，输出以下格式（只输出这一行）：
Final Answer: {{"vuln_type": "漏洞类型", "location": "函数名", "cause": "成因说明"}}

漏洞类型只能是：stack_buffer_overflow, heap_buffer_overflow, format_string, use_after_free, null_pointer_dereference

如果没发现漏洞，输出：
Final Answer: {{"vuln_type": "none", "location": "none", "cause": "未发现明显安全漏洞"}}

现在开始分析。首先分析 main 函数。
"""

    # 初始化智谱AI客户端
    client = ZhipuAiClient(api_key=ZHIPU_API_KEY)

    tools = [
        {
            "type": "function",
            "function": {
                "name": "run_r2_analysis",
                "description": "使用radare2分析函数，返回汇编代码",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "function_name": {
                            "type": "string",
                            "description": "要分析的函数名称",
                        }
                    },
                    "required": ["function_name"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_ghidra_decompile",
                "description": "使用Ghidra反编译函数，返回C伪代码",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "function_name": {
                            "type": "string",
                            "description": "要反编译的函数名称",
                        }
                    },
                    "required": ["function_name"],
                },
            },
        }
    ]

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "请分析 'challenge' 文件的安全漏洞。先分析 main 函数。"}
    ]

    step = 0
    final_answer = None

    while step < 6 and final_answer is None:
        step += 1
        print(f"\n{'='*20} 第 {step} 轮交互 {'='*20}")

        print("[AI思考中...]")
        try:
            response = client.chat.completions.create(
                model="glm-4-plus",
                messages=messages,
                tools=tools,
                tool_choice="auto"
            )
        except Exception as e:
            print(f"[错误] API调用失败: {e}")
            break

        assistant_message = response.choices[0].message
        messages.append(assistant_message.model_dump())

        if assistant_message.content:
            print(f"\n[AI思考]\n{assistant_message.content}")

        if assistant_message.tool_calls:
            for tool_call in assistant_message.tool_calls:
                tool_name = tool_call.function.name
                try:
                    tool_args = json.loads(tool_call.function.arguments)
                    function_name = tool_args.get("function_name", "main")
                except:
                    function_name = "main"

                print(f"\n[行动] 调用工具: {tool_name}({function_name})")

                if tool_name == "run_r2_analysis":
                    observation_result = execute_r2_analysis(function_name)
                elif tool_name == "run_ghidra_decompile":
                    observation_result = execute_ghidra_decompile(function_name)
                else:
                    observation_result = f"未知工具: {tool_name}"

                preview = observation_result[:500] if len(observation_result) > 500 else observation_result
                print(f"\n[观察]\n{preview}...")

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": observation_result
                })
        else:
            content = assistant_message.content or ""
            if "Final Answer:" in content:
                json_match = re.search(r'Final Answer:\s*(\{.*\})', content, re.DOTALL)
                if json_match:
                    try:
                        final_answer = json.loads(json_match.group(1))
                        print(f"\n[最终答案]\n{json.dumps(final_answer, indent=2)}")
                    except:
                        print("\n[错误] JSON解析失败")
            else:
                print("\n[提示] AI本轮未调用工具，继续...")
                messages.append({
                    "role": "user",
                    "content": "请继续分析。如果找到漏洞，输出 Final Answer。否则调用工具获取更多信息。"
                })

        if step == 6 and final_answer is None:
            print("\n[警告] 达到最大轮数，使用默认结论")
            final_answer = {
                "vuln_type": "none",
                "location": "none",
                "cause": "未发现明显安全漏洞"
            }

    # ============================================================
    # 保存 vuln.json
    # ============================================================
    required_fields = ["vuln_type", "location", "cause"]
    valid_types = ["stack_buffer_overflow", "heap_buffer_overflow", "format_string", "use_after_free", "null_pointer_dereference", "none"]

    cleaned_answer = {}
    for field in required_fields:
        cleaned_answer[field] = final_answer.get(field, "unknown") if final_answer else "unknown"

    # 验证漏洞类型
    if cleaned_answer["vuln_type"] not in valid_types:
        if "stack" in cleaned_answer["vuln_type"].lower():
            cleaned_answer["vuln_type"] = "stack_buffer_overflow"
        elif "heap" in cleaned_answer["vuln_type"].lower():
            cleaned_answer["vuln_type"] = "heap_buffer_overflow"
        else:
            cleaned_answer["vuln_type"] = "none"

    # 保存 vuln.json
    with open("vuln.json", "w", encoding="utf-8") as f:
        json.dump(cleaned_answer, f, indent=2, ensure_ascii=False)

    print("\n[成功] 已生成 vuln.json")
    print("内容：")
    print(json.dumps(cleaned_answer, indent=2, ensure_ascii=False))

    # 保存日志
    os.makedirs("logs", exist_ok=True)
    with open("logs/run.txt", "w", encoding="utf-8") as f:
        f.write("=== ReAct Agent 完整交互日志 ===\n")
        f.write("模型: glm-4-plus (智谱AI)\n")
        f.write("工具: r2pipe (radare2 + Ghidra)\n\n")
        f.write(f"函数列表: {', '.join(functions)}\n\n")
        for msg in messages:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            if content:
                f.write(f"[{role.upper()}]\n{content}\n\n")
            if "tool_calls" in msg and msg["tool_calls"]:
                for tc in msg["tool_calls"]:
                    f.write(f"[TOOL_CALL] {tc['function']['name']}: {tc['function']['arguments']}\n\n")
    print("[成功] 已生成 logs/run.txt")

    print("\n" + "="*60)
    print("实验完成！")
    print(f"漏洞类型: {cleaned_answer.get('vuln_type')}")
    print(f"漏洞位置: {cleaned_answer.get('location')}")
    print("="*60)

# ============================================================
# 程序入口
# ============================================================
if __name__ == "__main__":
    if not os.path.exists("challenge"):
        print("[错误] 找不到 'challenge' 文件！请确保它和脚本在同一目录。")
    elif ZHIPU_API_KEY == "021086629fd04c40a838654246c3b8f8.EdLBepOu7IFhTDEF":
        # 这里可以继续运行，API Key 已经填了
        run_agent()
    else:
        run_agent()