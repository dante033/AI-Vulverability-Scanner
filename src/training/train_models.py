import pandas as pd
import torch
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sentence_transformers import SentenceTransformer
import joblib
from transformers import T5ForConditionalGeneration, T5Tokenizer, Trainer, TrainingArguments

# 1) Device and memory check
device = 'cuda' if torch.cuda.is_available() else 'cpu'
print(f"Using device: {device}")
if device == 'cuda':
    print(f"GPU detected: {torch.cuda.get_device_name(0)}")
    print(f"CUDA memory allocated before training: {torch.cuda.memory_allocated()/1e9:.2f} GB")

# 2) Paths
root = Path(__file__).parents[2]
data_dir = root / 'data' / 'processed'
model_dir = root / 'models'
model_dir.mkdir(exist_ok=True)

# 3) Load full dataset with remediations
csv_path = data_dir / 'cve_full_dataset.csv'
df = pd.read_csv(csv_path)
print(f"Loaded full dataset with {len(df)} rows (expected ~79944)")
assert len(df) >= 79944, "Dataset truncated: run retrieve_remediations.py to regenerate full CSV"

# 4) Severity classifier on SBERT embeddings
X = df['Description'].tolist()
y_map = {'LOW':0, 'MEDIUM':1, 'HIGH':2, 'CRITICAL':3, 'UNKNOWN':-1}
y = [y_map.get(lbl, -1) for lbl in df['Severity']]

embedder = SentenceTransformer('all-MiniLM-L6-v2', device=device)
X_emb = embedder.encode(X, convert_to_tensor=False)
print(f"Computed embeddings for {len(X_emb)} examples")

# 90/10 train/validation split
train_n = int(0.9 * len(X_emb))
print(f"Training on {train_n} examples, validating on {len(X_emb)-train_n}")
X_train, X_val, y_train, y_val = train_test_split(X_emb, y, test_size=0.1, random_state=42)

clf = RandomForestClassifier(n_estimators=100)
clf.fit(X_train, y_train)
print("Severity classifier performance on validation set:")
print(classification_report(y_val, clf.predict(X_val), zero_division=0))
joblib.dump(clf, model_dir/'severity_classifier.pkl')

# 5) T5 remediation fine‑tuning
tokenizer = T5Tokenizer.from_pretrained('t5-small')
rem_model = T5ForConditionalGeneration.from_pretrained('t5-small').to(device)

class CVEDataset(torch.utils.data.Dataset):
    def __init__(self, df, tokenizer, max_len=256):
        self.inputs = ['remediate: ' + d for d in df['Description']]
        self.targets = df['Remediation_Steps'].tolist()
        self.tokenizer = tokenizer
        self.max_len = max_len
    def __len__(self):
        return len(self.inputs)
    def __getitem__(self, idx):
        enc = self.tokenizer(
            self.inputs[idx], truncation=True, padding='max_length',
            max_length=self.max_len, return_tensors='pt'
        )
        dec = self.tokenizer(
            self.targets[idx], truncation=True, padding='max_length',
            max_length=self.max_len, return_tensors='pt'
        )
        return {
            'input_ids': enc.input_ids.squeeze().to(device),
            'attention_mask': enc.attention_mask.squeeze().to(device),
            'labels': dec.input_ids.squeeze().to(device)
        }

# Prepare datasets and training arguments
full_dataset = CVEDataset(df, tokenizer)
train_ds, val_ds = torch.utils.data.random_split(
    full_dataset, [train_n, len(full_dataset) - train_n]
)

training_args = TrainingArguments(
    output_dir=str(model_dir),
    per_device_train_batch_size=8,       # increased batch size for speed
    per_device_eval_batch_size=8,
    num_train_epochs=3,
    logging_steps=500,
    save_total_limit=1,
    fp16=(device=='cuda'),
    evaluation_strategy='steps',
    eval_steps=1000
)

print("Starting T5 fine‑tuning…")
trainer = Trainer(
    model=rem_model,
    args=training_args,
    train_dataset=train_ds,
    eval_dataset=val_ds,
    tokenizer=tokenizer
)
trainer.train()
print("Fine‑tuning complete.")

# GPU memory after training
if device=='cuda':
    print(f"CUDA memory allocated after training: {torch.cuda.memory_allocated()/1e9:.2f} GB")

rem_model.save_pretrained(model_dir, safe_serialization=True)
print('Saved remediation_model.safetensors')