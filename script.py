import ollama 
from database import Session, CVE
import numpy as np 
import sqlite3

session = Session()
emb = sqlite3.connect('embeddings.db')
emb.execute("""CREATE TABLE IF NOT EXISTS embeddings(
            cve_id TEXT NOT NULL,
            port INTEGER,
            embedding BLOB NOT NULL,
            PRIMARY KEY (cve_id,port))""")
emb.commit()
             

EMBEDDING_MODEL = 'hf.co/CompendiumLabs/bge-base-en-v1.5-gguf'
LANGUAGE_MODEL = 'hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF'

VECTOR_DB = [] 

def add_chunk_to_db(chunk,row): 
    embedding = ollama.embed(model=EMBEDDING_MODEL, input=chunk)['embeddings'][0]
    VECTOR_DB.append({"chunk": chunk, 
                     "embedding": embedding, 
                     "cve_id": row.cve_id,
                       "port": row.port, 
                       "cvss": row.cvss})



def save_embedding(cve_id,port,embedding):

    blob = np.array(embedding,dtype=np.float32).tobytes()
    emb.execute("INSERT OR IGNORE INTO embeddings (cve_id,port,embedding) VALUES (?,?,?)", (cve_id,port,blob))
    emb.commit()

def load_embedding(): 
    VECTOR_DB.clear()
    rows = emb.execute("SELECT cve_id, port, embedding FROM embeddings").fetchall()
    for cve_id,port,blob in rows: 
       vector = np.frombuffer(blob, dtype=np.float32).tolist() 
       cve_row = session.query(CVE).filter_by(cve_id=cve_id, port=port).first()
       if cve_row:
            severity = (
    "Critical" if cve_row.cvss >= 9 else
    "High" if cve_row.cvss >= 7 else
    "Medium" if cve_row.cvss >= 4 else
    "Low"
            )

            chunk = f"""
            CVE ID: {cve_row.cve_id}
            Port: {cve_row.port}
            Application: {cve_row.application}
            Severity: {severity}
            CVSS Score: {cve_row.cvss}
            Description: {cve_row.description}
            """
            VECTOR_DB.append({
                "chunk": chunk,
                "embedding": vector,
                "cve_id": cve_id,
                "port": port,
                "cvss": cve_row.cvss
            })


def get_unembedded(): 
    embedded = set(
        emb.execute(
            "SELECT cve_id, port FROM embeddings"
        ).fetchall()
    )
    all_rows = session.query(CVE).all()
    return [
        r for r in all_rows
        if (r.cve_id, r.port) not in embedded
    ]


def init_embed_db(): 
    load_embedding()
    missin = get_unembedded()
    for row in missin:

        severity = (
    "Critical" if row.cvss >= 9 else
    "High" if row.cvss >= 7 else
    "Medium" if row.cvss >= 4 else
    "Low") 
        chunk = f"""
        CVE ID: {row.cve_id}
        Port: {row.port}
        Application: {row.application}
        Severity: {severity}
        CVSS Score: {row.cvss}
        Description: {row.description}
        """
        embedding = ollama.embed(
            model=EMBEDDING_MODEL,
            input=chunk
        )["embeddings"][0]

        save_embedding(
            row.cve_id,
            row.port,
            embedding
        )

        VECTOR_DB.append({
            "chunk": chunk,
            "embedding": embedding,
            "cve_id": row.cve_id,
            "port": row.port,
            "cvss": row.cvss
        }) 
    emb.commit()


"""rows = session.query(CVE).all()
for i in rows:
    chunk = f
        CVE: {i.cve_id}
        Port: {i.port}
        Application: {i.application}
        CVSS: {i.cvss}
        Description: {i.description}

    add_chunk_to_db(chunk,i)"""

def cosine_similarity(a, b):
  if len(a) != len(b):
        raise ValueError(
            f"Embedding size mismatch: {len(a)} vs {len(b)}"
        )
  dot_product = sum(x * y for x, y in zip(a, b))
  norm_a = sum(x * x for x in a) ** 0.5
  norm_b = sum(x * x for x in b) ** 0.5 
  
  if norm_a == 0 or norm_b == 0:
        return 0
  return dot_product / (norm_a * norm_b)


def retrieve(query, top_n=3):
  query_embedding = ollama.embed(model=EMBEDDING_MODEL, input=query)['embeddings'][0]
  # temporary list to store (chunk, similarity) pairs
  similarities = []
  for item in VECTOR_DB:
    similarity = cosine_similarity(query_embedding, item["embedding"])
    similarities.append({
    "chunk": item["chunk"],
    "similarity": similarity,
    "cve_id": item["cve_id"],
    "port": item["port"],
    "cvss": item["cvss"]
    })

  # sort by similarity in descending order, because higher similarity means more relevant chunks
  similarities.sort(key=lambda x: x["similarity"], reverse=True)
  # finally, return the top N most relevant chunks
  return similarities[:top_n]

def retrieve_by_port(port,top_n=5): 
   matches = [item for item in VECTOR_DB if item["port"]== port]
   matches.sort(key=lambda x:x["cvss"], reverse=True)
   return matches[:top_n]

init_embed_db()

input_query = input('Ask me a question: ')
retrieved_knowledge = retrieve(input_query)

print('Retrieved knowledge:')
for item in retrieved_knowledge:
    print(
        f'\nCVE: {item["cve_id"]}'
        f'\nPort: {item["port"]}'
        f'\nCVSS: {item["cvss"]}'
        f'\nSimilarity: {item["similarity"]:.3f}'
    )

context = "\n\n".join(
    item["chunk"]
    for item in retrieved_knowledge
)

instruction_prompt = f"""
You are a cybersecurity assistant.

Use only the provided CVE information
to answer the user's question.

If the answer is not contained in the
context, say that you do not know.

Context:

{context}
"""

stream = ollama.chat(
  model=LANGUAGE_MODEL,
  messages=[
    {'role': 'system', 'content': instruction_prompt},
    {'role': 'user', 'content': input_query},
  ],
  stream=True,
)

# print the response from the chatbot in real-time
print('Chatbot response:')
for chunk in stream:
  print(chunk['message']['content'], end='', flush=True)
