import gradio as gr
from workflow import pcap_workflow

theme = gr.themes.Soft(
    primary_hue="blue",
    secondary_hue="blue",
    neutral_hue="slate"
)

with gr.Blocks(theme=theme, title="PCAP → Neo4j") as demo:

    gr.Markdown("# 🐬 PCAP → Neo4j")

    gr.Markdown("### Configure Neo4j Database")
    neo4j_url = gr.Text(label="URL", value="bolt://localhost:7687")
    neo4j_user = gr.Text(label="User", value="neo4j")
    neo4j_password = gr.Text(label="Password", type="password")
    neo4j_input_dir = gr.Text(label="Import Directory")

    gr.Markdown("### Set Upload Parameters")
    folder_input = gr.File(
        label="Upload PCAPs",
        file_types=[".pcap", ".pcapng", ".cap", ".pcapppi"],
        file_count="multiple"
    )


    mission = gr.Text(label="Mission Name")

    submit = gr.Button("Ingest into Neo4j")
    output = gr.Textbox(label="Output", lines=3)

    submit.click(
        fn=pcap_workflow,
        inputs=[folder_input, mission, neo4j_url, neo4j_user, neo4j_password, neo4j_input_dir],
        outputs=output
    )

demo.launch(favicon_path="dolphin.svg",inbrowser=True)
