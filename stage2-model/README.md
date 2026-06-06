# Stage 2 Model

Stage 2 releases the first open RealMythos security reasoning model:

[RealMythos/pocwriter-v1](https://huggingface.co/RealMythos/pocwriter-v1)

`pocwriter-v1` is a full-parameter supervised fine-tune of [Qwen/Qwen3.5-9B](https://huggingface.co/Qwen/Qwen3.5-9B), trained on [RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning). It is specialized for authorized security research tasks such as C/C++ vulnerability analysis, proof-of-concept drafting in controlled environments, and triage/write-up assistance.

## Release Metadata

| Item | Current value |
|---|---|
| Hugging Face model | [RealMythos/pocwriter-v1](https://huggingface.co/RealMythos/pocwriter-v1) |
| Base model | [Qwen/Qwen3.5-9B](https://huggingface.co/Qwen/Qwen3.5-9B) |
| Training data | [RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning) |
| Method | Full-parameter supervised fine-tuning |
| Framework | LLaMA-Factory with DeepSpeed ZeRO |
| Checkpoint | Stage-1 SFT checkpoint 748 |
| Precision | bf16 |
| License | Apache-2.0 |

## Intended Use

- Vulnerability reasoning and source-code analysis for authorized security research
- PoC drafting for controlled validation on systems the user owns or is explicitly authorized to test
- Triage notes, reproduction guidance, and write-up assistance
- Defensive model evaluation and academic study of security reasoning behavior

## Out of Scope

- Unauthorized exploitation or testing against systems without explicit written permission
- Offensive scanning of real-world targets
- Automated vulnerability weaponization
- Deployment as an unsupervised exploit-generation service

## Basic Inference Example

```python
from transformers import AutoModelForCausalLM, AutoTokenizer

model_id = "RealMythos/pocwriter-v1"
tok = AutoTokenizer.from_pretrained(model_id)
model = AutoModelForCausalLM.from_pretrained(
    model_id,
    torch_dtype="auto",
    device_map="auto",
)

messages = [
    {
        "role": "user",
        "content": "Analyze this authorized test function for memory-safety issues and summarize any validation steps:\n<code here>",
    },
]
inputs = tok.apply_chat_template(
    messages,
    add_generation_prompt=True,
    return_tensors="pt",
).to(model.device)
out = model.generate(inputs, max_new_tokens=512)
print(tok.decode(out[0][inputs.shape[-1]:], skip_special_tokens=True))
```

If the local Transformers version resolves this checkpoint as an image-text-to-text model, load it with the matching `AutoProcessor` and `AutoModelForImageTextToText` classes described by the Hugging Face model metadata.

## Limitations

- `pocwriter-v1` is an early public checkpoint and may change in future RealMythos releases.
- The training distribution is concentrated on English C/C++ CVE-linked vulnerability reasoning, with a strong memory-safety focus.
- Outputs may be incomplete, non-executable, or incorrect; users must manually verify all findings and generated PoCs.
- Public performance claims should be tied to exact evaluation settings, baselines, and released evaluation artifacts.

## Dependency on Stage 1

The model release is linked to the Stage 1 dataset used for training. Dataset documentation, reproducibility pipeline notes, and responsible-use guidance are maintained under [`stage1-dataset/`](../stage1-dataset/) and [`docs/`](../docs/).
