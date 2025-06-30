import gradio as gr
from pathlib import Path
import requests
import pandas as pd

def get_server_status_for_gui(current_servers_config):
    status_data = []
    try:
        for name, details in current_servers_config:

            if isinstance(details, dict) and 'url' in details and 'queue' in details:
                server_url = details['url']
                queue_size = details['queue'].qsize() if hasattr(details['queue'], 'qsize') else 'N/A'

                running_models_str = "N/A"  # Default
                api_ps_url = f"{server_url.rstrip('/')}/api/ps"

                try:
                    response = requests.get(api_ps_url, timeout=5)
                    if response.status_code == 200:
                        ps_data = response.json()
                        if ps_data and "models" in ps_data and isinstance(ps_data["models"], list):
                            model_names = [model.get("name", "UnknownModel") for model in ps_data["models"]]
                            if model_names:
                                running_models_str = "; ".join(model_names)
                            else:
                                running_models_str = "None"
                        else:
                            running_models_str = "No model data"
                    elif response.status_code == 404:
                        running_models_str = "Unsupported (old Ollama?)"
                    else:
                        running_models_str = f"Error: HTTP {response.status_code}"
                except Exception as e_ps:
                    running_models_str = "Fetch Error"
                    print(f"GUI: Error fetching /api/ps for server {name}: {e_ps}")

                status_data.append([name, server_url, queue_size, running_models_str])
            else:
                print(f"GUI Warning: Malformed server entry in config: '{name}': {details}")
                status_data.append([name, "Invalid Config", "N/A", "N/A"])

        if not status_data:
            print("GUI: current_servers_config was present, but status_data is empty. Returning default empty row.")
            return [["No valid server data found.", "", "", ""]]
        return status_data
    except Exception as e:
        print(f"GUI Error: Exception in get_server_status_for_gui: {e}")
        import traceback
        traceback.print_exc()
        return [["Error processing server data.", str(e), "", ""]]  # Match column count


def get_access_logs_for_gui(log_file_path_str, num_lines=100):
    """
    Reads the last N lines from the access log file.
    """
    log_file_path = Path(log_file_path_str)
    if not log_file_path.exists():
        print(f"GUI Warning: Log file '{log_file_path}' not found.")
        return "Log file not found."

    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        start_index = max(0, len(lines) - num_lines)
        log_content = "".join(lines[start_index:])

        if not log_content.strip():
            return "Log file is empty or contains only whitespace."

        return log_content
    except Exception as e:
        print(f"GUI Error: Exception in get_access_logs_for_gui: {e}")
        import traceback
        traceback.print_exc()
        return f"Error reading log file: {str(e)}"


def get_models(models_file_path):
    models_file_path = Path(models_file_path)
    if not models_file_path.exists():
        print(f"GUI Warning: Models file '{models_file_path}' not found.")
        return "Models file not found."

    try:
        return pd.read_csv(models_file_path)

    except Exception as e:
        print(f"GUI Error: Exception in get_models while loading models from file {models_file_path} :: {e}")
        return None


def save_models(models, models_file_path):
    df = pd.DataFrame(models, columns=['Model'])
    df.to_csv(models_file_path, index=False, encoding='utf-8')


def get_worker_status(server_config, models_file_path):
    worker_status_list = []

    # Step 1: get worker info
    server_status = get_server_status_for_gui(server_config)

    # Step 2: load global models
    global_models_df = get_models(models_file_path)
    if global_models_df is None or 'Model' not in global_models_df.columns:
        print("GUI Warning: Global models file missing or malformed.")
        return pd.DataFrame([["Global models config error", "Unable to load models"]], columns=["Worker", "Status"])

    global_models = set(global_models_df['Model'].dropna().astype(str).str.strip())

    # Step 3: For each worker, fetch available models and compare
    for worker_entry in server_status:
        if len(worker_entry) < 2:
            continue
        worker_name = worker_entry[0]
        worker_url = worker_entry[1]

        api_tags_url = f"{worker_url.rstrip('/')}/api/tags"
        try:
            resp = requests.get(api_tags_url, timeout=5)
            if resp.status_code != 200:
                status_msg = f"Fetch Error: HTTP {resp.status_code}"
                worker_status_list.append([worker_name, status_msg, ""])
                continue

            tags_data = resp.json()

            if isinstance(tags_data, dict) and "models" in tags_data:
                worker_models = set(str(m.get("name", "")).strip() for m in tags_data["models"])
            else:
                worker_status_list.append([worker_name, "Fetch Error: Unexpected response format", ""])
                continue

            missing_models = global_models - worker_models
            extra_models = worker_models - global_models

            status = "OK" if not missing_models else f"Missing: {', '.join(sorted(missing_models))}"
            extra_str = ", ".join(sorted(extra_models)) if extra_models else ""

            worker_status_list.append([worker_name, status, extra_str])

        except Exception as e:
            worker_status_list.append([worker_name, f"Fetch Error: {str(e)}", ""])

    return pd.DataFrame(worker_status_list, columns=["Worker", "Status", "Additional models"])


def update_workers(worker_status, server_config):
    logs = []

    server_status = get_server_status_for_gui(server_config)

    for worker in worker_status.itertuples(index=False):

        status = getattr(worker, "Status")
        if status == "OK":
            continue

        worker_name = getattr(worker, "Worker")
        url = next((entry[1] for entry in server_status if entry[0] == worker_name), "")

        logs.append([f"[Updating {worker_name}] :: {url}"])

        if status.startswith("Missing: "):
            models = status.replace("Missing: ", "").split(", ")
            for model in models:
                if model.strip():
                    logs.append(f' - pulling:  {model.strip()}')

    if not logs:
        logs.append("No updates needed.")

    return "\n".join(
        line[0] if isinstance(line, list) else line
        for line in logs
    )



def create_gui(server_config, log_file_path, models_file_path):
    """
    Creates the Gradio interface.
    """
    default_log_lines = 50

    with gr.Blocks(title="Ollama Proxy Manager") as demo:
        gr.Markdown("# Ollama Proxy Server Management")

        with gr.Tabs():
            with gr.TabItem("Servers"):
                gr.Markdown("## Configured Ollama Servers")
                server_list_output = gr.DataFrame(
                    headers=["Name", "URL", "Queue Size", "Running Models"],
                    interactive=False,
                    row_count=(10, "dynamic")
                )
                refresh_servers_btn = gr.Button("Refresh Server List")

                refresh_servers_btn.click(
                    fn=lambda: get_server_status_for_gui(server_config),
                    inputs=None,
                    outputs=server_list_output
                )

            with gr.TabItem("Logs"):
                gr.Markdown("## Access Log Viewer")

                with gr.Row():
                    log_lines_input = gr.Number(
                        value=default_log_lines,
                        label="Number of log lines",
                        minimum=1,
                        step=1,
                        precision=0
                    )
                    refresh_logs_btn = gr.Button("Refresh Logs")

                log_output_textbox = gr.Textbox(
                    label="Log Entries",
                    lines=20,
                    max_lines=30,
                    interactive=False,
                    show_copy_button=True
                )

                def update_logs_display(lines_to_show_from_input):
                    return get_access_logs_for_gui(log_file_path, num_lines=int(lines_to_show_from_input))

                refresh_logs_btn.click(
                    fn=update_logs_display,
                    inputs=[log_lines_input],
                    outputs=log_output_textbox
                )

            with gr.TabItem("Models"):
                with gr.Row():
                    # left column
                    with gr.Column(scale=1):
                        gr.Markdown("## Global Models")

                        # list of models
                        models = gr.DataFrame(
                            headers=["Model"],
                            interactive=True,
                            row_count=(5, "dynamic")
                        )
                        gr.Markdown("(Edit table to change model configuration)")

                    # right column
                    with gr.Column(scale=1):
                        gr.Markdown("## Manage Workers")

                        worker_status = gr.DataFrame(
                            headers=["Worker", "Status", "Additional models"],
                            interactive=False,
                            row_count=(10, "dynamic")
                        )

                        update_logs = gr.Textbox(
                            label="Update Log",
                            lines=10,
                            max_lines=20,
                            interactive=False,
                            show_copy_button=True
                        )

                        update_workers_btn = gr.Button("Pull missing models")

            with gr.TabItem("Users"):
                with gr.Row():
                    with gr.Column(scale=1):
                        gr.Markdown("## Registered Users")

                        users = gr.DataFrame(
                            headers=["UserID", "Expiration Date"],
                            interactive=False,
                            row_count=(10, "dynamic")
                        )
                        gr.Markdown("(Edit table to change user configuration, users with past expiration dates will be removed automatically)")

                    with gr.Column(scale=1):
                        gr.Markdown("## Other Stuff!")

                # ------> events <------
                models.change(
                    fn=lambda models: save_models(models, models_file_path),
                    inputs=[models],
                    outputs=[]
                )
                models.change(
                    fn=lambda: get_worker_status(server_config, models_file_path),
                    inputs=None,
                    outputs=worker_status
                )
                update_workers_btn.click(
                    fn=lambda worker_status: update_workers(worker_status, server_config),
                    inputs=[worker_status],
                    outputs=update_logs
                )


        # Initial loads
        demo.load(
            fn=lambda: get_server_status_for_gui(server_config),
            inputs=None,
            outputs=server_list_output
        )
        demo.load(
            fn=lambda: get_access_logs_for_gui(log_file_path, num_lines=default_log_lines),
            inputs=None,
            outputs=log_output_textbox
        )
        demo.load(
            fn=lambda: get_models(models_file_path=models_file_path),
            inputs=None,
            outputs=models
        )
        demo.load(
            fn=lambda: get_worker_status(server_config, models_file_path),
            inputs=None,
            outputs=worker_status
        )


    return demo


def launch_gui(gui_port_to_use, server_config, log_file_path, models_file_path):
    """
    Launches the Gradio GUI.
    Passes the server config getter to create_gui.

    launch command: python main.py --config ../config.ini --users_list ../authorized_users.txt --log_path access_log.txt --port 8000 --gui_port 7860 --model ../models.txt
    """
    print("GUI: Attempting to launch Gradio GUI...")
    gui_app = create_gui(server_config, log_file_path, models_file_path)
    try:
        gui_app.launch(server_name="localhost", server_port=int(gui_port_to_use), share=False)
        print(f"GUI: Gradio GUI is running on http://localhost:{gui_port_to_use}")
    except Exception as e:
        print(f"GUI Error: Failed to launch Gradio GUI: {e}")
