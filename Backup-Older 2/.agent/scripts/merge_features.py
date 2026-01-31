import json
import os

# Paths
PLUGIN_DIR = r"t:\~\Local925 Sites\vaptbuilder\app\public\wp-content\plugins\VAPTBuilder"
CORE_JSON_PATH = os.path.join(PLUGIN_DIR, "data", "Feature-List-87.JSON")
SKILL_JSON_PATH = os.path.join(PLUGIN_DIR, ".agent", "skills", "wordpress-vapt-expert", "resources", "features-database.json")
OUTPUT_PATH = os.path.join(PLUGIN_DIR, "data", "Feature-List-87-Unified.json")

def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json(data, path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Saved unified JSON to: {path}")

def main():
    print("Loading JSON files...")
    core_data = load_json(CORE_JSON_PATH)
    skill_data = load_json(SKILL_JSON_PATH)

    # Normalize Core Data (Handle Array vs Object)
    core_features = core_data if isinstance(core_data, list) else core_data.get('features', [])
    
    # Normalize Skill Data
    skill_features = skill_data if isinstance(skill_data, list) else skill_data.get('features', [])
    
    # Create a lookup map for Skill IDs based on Feature Name
    skill_id_map = {f['name'].strip().lower(): f.get('id') for f in skill_features if 'name' in f}

    print(f"Loaded {len(core_features)} core features.")
    print(f"Loaded {len(skill_features)} skill features for ID mapping.")

    unified_features = []
    matched_count = 0

    for feature in core_features:
        name_key = feature.get('name', '').strip().lower()
        
        # Try exact match
        skill_id = skill_id_map.get(name_key)
        
        # Fallback: simple slugification if no match
        if not skill_id:
            print(f"Warning: No ID match for '{feature.get('name')}'. Generating slug.")
            skill_id = feature.get('name', '').lower().replace(' ', '-').replace('(', '').replace(')', '')

        # Inject ID at the beginning
        new_feature = {'id': skill_id}
        new_feature.update(feature)
        unified_features.append(new_feature)
        
        if skill_id_map.get(name_key):
            matched_count += 1

    print(f"Matched {matched_count} IDs from Skill DB.")

    # Construct Final Object
    final_output = {
        "metadata": {
            "version": "2.5.5",
            "source": "VAPT Builder Unified Core",
            "total_features": len(unified_features),
            "generated_at": "2026-01-20"
        },
        "features": unified_features
    }

    save_json(final_output, OUTPUT_PATH)

if __name__ == "__main__":
    main()
