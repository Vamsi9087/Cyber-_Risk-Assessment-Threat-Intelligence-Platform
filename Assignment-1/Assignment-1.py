import requests
import json


url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

response=requests.get(url)

data=response.json()

#here iam checking the data 
print(type(data))

# it was in dict   and what are the keys are there 
print(data.keys())  

#here total  attack-pattern
techniques = []

for obj in data["objects"]:
    if obj.get("type") == "attack-pattern":
        techniques.append(obj)

print("Total Attack Techniques:", len(techniques))

#Check techniques
print(type(techniques))
print(techniques[0].keys())      # See available fields
print(techniques[0]["name"])     # Technique name

#2

print('- '* 40)
def threat_score(tech):
    score = 5   # A. Base Score

    # Safe access + lowercase conversion
    name = tech.get("name", "").lower()
    description = tech.get("description", "").lower()

    # B. Name-Based Intelligence
    if "credential" in name:
        score += 3
    if "execution" in name:
        score += 2
    if "privilege" in name:
        score += 3
    if "persistence" in name:
        score += 2
    if "lateral" in name:
        score += 2

    # C. Description-Based Intelligence (NEW FACTOR)
    if "administrator" in description:
        score += 2   # high privilege access
    if "remote" in description:
        score += 2   # remote attacks increase exposure
    if "bypass" in description:
        score += 2   # security controls avoided
    if "stealth" in description:
        score += 1   # harder detection

    return score

scored_techniques = []

for tech in techniques:
    score = threat_score(tech)
    scored_techniques.append({
        "name": tech.get("name"),
        "score": score
    })

# Sort high → low
scored_techniques = sorted(
    scored_techniques,
    key=lambda x: x["score"],
    reverse=True
)

# Top 10 High-Risk Techniques
print("Top 10 High-Risk Techniques:")
for t in scored_techniques[:10]:
    print(t["name"], "-> Score:", t["score"])



#question no 3
print('-'*40)
# Step 1: Define Threat Scoring Function
def threat_score(tech):
    
    score = 5  # Base score
    
    name = tech["name"].lower()
    
    # High Risk Keywords (+3)
    high_risk = ["credential", "privilege", "admin", "root", "password"]
    
    # Medium Risk Keywords (+2)
    medium_risk = ["execution", "persistence", "lateral", "remote", "command"]
    
    # Critical Impact Keywords (+4)
    critical = ["exfiltration", "ransomware", "impact", "encrypted"]
    
    for word in high_risk:
        if word in name:
            score += 3
            
    for word in medium_risk:
        if word in name:
            score += 2
            
    for word in critical:
        if word in name:
            score += 4
            
    return score


# Step 2: Score All Techniques
scored_techniques = []

for tech in techniques:
    score = threat_score(tech)
    
    # Store as ("Technique Name", score)
    scored_techniques.append((tech["name"], score))


# Step 3: Verify Output
print("Total Techniques Scored:", len(scored_techniques))
print("\nFirst 5 Scored Techniques:")
print(scored_techniques[:5])

#4 question
print('-'*40)
scored_techniques = []

for tech in techniques:
    score = threat_score(tech)
    scored_techniques.append((tech["name"], score))

# Sort by score (High to Low)
scored_techniques.sort(key=lambda x: x[1], reverse=True)

print("Top 10 High Risk Techniques:\n")

for tech in scored_techniques[:10]:
    print(tech)

#question5
print('-'*40)

print("\nCritical Threats (Score >= 8.9):\n")

for technique, score in scored_techniques:
    if score >= 8.9:
        print(f"{technique} — Score: {score}")

