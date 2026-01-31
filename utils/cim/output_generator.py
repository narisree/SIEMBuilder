"""
Output Generator for CIM Mappings
Generates GUI instructions (Splunk Cloud) and config files (Splunk Enterprise).
Properly separates Calculated Fields (flag: calculated) from Field Aliases (flag: extracted).
"""
import re
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class FieldMapping:
    """Represents a single field mapping."""
    raw_field: str
    cim_field: str
    transformation: str
    field_flag: str  # 'calculated' or 'extracted'
    requirement: str
    notes: str
    eval_expression: Optional[str] = None


class OutputGenerator:
    """Generates output in multiple formats based on deployment mode."""
    
    def __init__(self, deployment_mode: str = "both"):
        """Initialize output generator."""
        self.deployment_mode = deployment_mode.lower()
    
    def generate_output(self, mapping_result: Dict, sourcetype: str) -> Dict[str, str]:
        """Generate output based on deployment mode."""
        outputs = {}
        
        mapping_text = mapping_result.get('mapping', '')
        data_model = mapping_result.get('data_model', 'Unknown')
        dataset = mapping_result.get('dataset', 'Unknown')
        
        # Parse the mapping result
        calculated_fields, extracted_fields = self._parse_mapping_result(mapping_text)
        tags = self._extract_tags(mapping_text)
        eval_expressions = self._extract_eval_expressions(mapping_text)
        
        # Merge eval expressions into calculated fields
        for cf in calculated_fields:
            if cf.cim_field in eval_expressions:
                cf.eval_expression = eval_expressions[cf.cim_field]
        
        if self.deployment_mode in ['cloud', 'both']:
            outputs['gui_instructions'] = self._generate_gui_instructions(
                calculated_fields, extracted_fields, sourcetype, 
                data_model, dataset, tags
            )
        
        if self.deployment_mode in ['enterprise', 'both']:
            outputs['props_conf'] = self._generate_props_conf(
                calculated_fields, extracted_fields, sourcetype, 
                data_model, dataset
            )
            outputs['transforms_conf'] = self._generate_transforms_conf(sourcetype)
            outputs['eventtypes_conf'] = self._generate_eventtypes_conf(sourcetype, data_model)
            outputs['tags_conf'] = self._generate_tags_conf(sourcetype, data_model, tags)
        
        outputs['validation_spl'] = self._generate_validation_spl(
            sourcetype, data_model, dataset, calculated_fields, extracted_fields
        )
        
        return outputs
    
    def _parse_mapping_result(self, mapping_text: str) -> tuple:
        """Parse the LLM mapping result into calculated and extracted field lists."""
        calculated_fields = []
        extracted_fields = []
        
        if not mapping_text:
            return calculated_fields, extracted_fields
        
        # Look for the mapping table
        lines = mapping_text.split('\n')
        in_table = False
        
        for line in lines:
            # Check if this is a table row
            if '|' in line and line.count('|') >= 4:
                parts = [p.strip() for p in line.split('|')]
                parts = [p for p in parts if p]  # Remove empty parts
                
                if len(parts) < 3:
                    continue
                
                # Skip header rows
                if any(h.lower() in ['raw field', 'cim field', 'field flag', '---', ':---'] 
                       for h in parts[:3]):
                    in_table = True
                    continue
                
                if not in_table:
                    continue
                
                raw_field = parts[0].strip('`* ')
                cim_field = parts[1].strip('`* ')
                
                # Skip invalid entries
                if not raw_field or not cim_field:
                    continue
                if raw_field.lower() in ['raw field name', 'raw field', '---', '#']:
                    continue
                if '---' in raw_field:
                    continue
                
                # Determine field flag
                field_flag = 'extracted'
                transformation = 'Field Alias'
                eval_expr = None
                
                for part in parts[2:]:
                    part_lower = part.lower().strip()
                    if 'calculated' in part_lower:
                        field_flag = 'calculated'
                        transformation = 'Calculated Field'
                    elif 'extracted' in part_lower:
                        field_flag = 'extracted'
                        transformation = 'Field Alias'
                    if 'eval' in part_lower or '(' in part:
                        # This might contain an expression
                        if '=' in part or '(' in part:
                            eval_expr = part.strip('`')
                
                requirement = parts[4].strip() if len(parts) > 4 else 'Optional'
                notes = parts[5].strip() if len(parts) > 5 else ''
                
                mapping = FieldMapping(
                    raw_field=raw_field,
                    cim_field=cim_field,
                    transformation=transformation,
                    field_flag=field_flag,
                    requirement=requirement,
                    notes=notes,
                    eval_expression=eval_expr
                )
                
                if field_flag == 'calculated':
                    calculated_fields.append(mapping)
                else:
                    extracted_fields.append(mapping)
        
        return calculated_fields, extracted_fields
    
    def _extract_tags(self, mapping_text: str) -> List[str]:
        """Extract required tags from mapping result."""
        tags = []
        
        if not mapping_text:
            return tags
        
        # Look for tags in code blocks
        tags_match = re.search(r'Required Tags.*?```\s*\n(.*?)```', mapping_text, re.DOTALL | re.IGNORECASE)
        if tags_match:
            for line in tags_match.group(1).strip().split('\n'):
                tag = line.strip()
                if tag and tag not in tags:
                    tags.append(tag)
        
        # Look for tags in lists
        if not tags:
            tags_match = re.search(r'Required Tags[:\s]*\n((?:[-*]\s*\w+\n?)+)', mapping_text, re.IGNORECASE)
            if tags_match:
                for line in tags_match.group(1).strip().split('\n'):
                    tag = line.strip('- *').strip()
                    if tag and tag not in tags:
                        tags.append(tag)
        
        # Defaults
        if not tags:
            if 'Network_Traffic' in mapping_text:
                tags = ['network', 'communicate']
            elif 'Authentication' in mapping_text:
                tags = ['authentication']
        
        return tags
    
    def _extract_eval_expressions(self, mapping_text: str) -> Dict[str, str]:
        """Extract EVAL expressions from the mapping result."""
        expressions = {}
        
        if not mapping_text:
            return expressions
        
        # Pattern: EVAL-field = expression
        eval_matches = re.findall(r'EVAL-(\w+)\s*=\s*(.+?)(?:\n|$)', mapping_text)
        for field, expr in eval_matches:
            expressions[field] = expr.strip()
        
        return expressions
    
    def _generate_default_eval(self, field: FieldMapping) -> str:
        """Generate a default EVAL expression for a calculated field."""
        cim = field.cim_field.lower()
        raw = field.raw_field
        
        # Action field normalization
        if cim == 'action':
            return f'''case(
  lower({raw})=="allow" OR lower({raw})=="permit", "allowed",
  lower({raw})=="deny" OR lower({raw})=="block", "blocked",
  lower({raw})=="drop", "dropped",
  1=1, lower({raw})
)'''
        
        # Port fields need tonumber
        if 'port' in cim:
            return f'tonumber({raw})'
        
        # Bytes fields
        if cim in ['bytes', 'bytes_in', 'bytes_out']:
            return f'tonumber({raw})'
        
        # src/dest calculated from IP fields
        if cim == 'src':
            return f'coalesce(src_ip, src_host, {raw})'
        if cim == 'dest':
            return f'coalesce(dest_ip, dest_host, {raw})'
        
        # User field - extract from domain\\user
        if cim == 'user':
            return f'''if(match({raw}, "\\\\\\\\"), mvindex(split({raw}, "\\\\\\\\"), -1), {raw})'''
        
        # Transport/protocol normalization
        if cim == 'transport':
            return f'lower({raw})'
        
        # Default - just reference the field
        return f'{raw}'
    
    def _generate_gui_instructions(self, calculated_fields: List[FieldMapping],
                                   extracted_fields: List[FieldMapping],
                                   sourcetype: str, data_model: str,
                                   dataset: str, tags: List[str]) -> str:
        """Generate step-by-step GUI instructions for Splunk Cloud."""
        
        dm_safe = data_model.lower().replace(' ', '_') if data_model else 'unknown'
        
        instructions = f"""# Splunk Cloud GUI Configuration Instructions

## Overview
- **Data Model**: {data_model}
- **Dataset**: {dataset}
- **Sourcetype**: `{sourcetype}`
- **Required Tags**: {', '.join(tags) if tags else 'See data model documentation'}

**IMPORTANT**: This guide separates Field Aliases (for extracted fields) from Calculated Fields (for calculated fields) based on CIM field flag specifications.

---

## Step 1: Create Event Type

1. Navigate to **Settings → Event Types**
2. Click **New Event Type**
3. Configure:
   - **Name**: `{sourcetype}_{dm_safe}`
   - **Search String**: `sourcetype={sourcetype}`
   - **Tags**: {', '.join(tags) if tags else 'network, communicate'}
4. Click **Save**

---

## Step 2: Configure Field Aliases (EXTRACTED fields only)

**⚠️ IMPORTANT: Only use Field Aliases for fields with `flag: extracted` in the CIM specification.**

Navigate to **Settings → Fields → Field Aliases**

"""
        if extracted_fields:
            for i, field in enumerate(extracted_fields, 1):
                instructions += f"""### Field Alias {i}: {field.cim_field}

1. Click **New Field Alias**
2. Configure:
   - **Name**: `{sourcetype}_{field.cim_field}_alias`
   - **Apply to**: `sourcetype` = `{sourcetype}`
   - **Field Alias**: `{field.raw_field}` AS `{field.cim_field}`
3. Click **Save**

"""
        else:
            instructions += "_No Field Aliases needed - all mappings require Calculated Fields._\n\n"
        
        instructions += """---

## Step 3: Configure Calculated Fields (CALCULATED fields only)

**⚠️ IMPORTANT: Only use Calculated Fields for fields with `flag: calculated` in the CIM specification.**

Navigate to **Settings → Fields → Calculated Fields**

"""
        if calculated_fields:
            for i, field in enumerate(calculated_fields, 1):
                eval_expr = field.eval_expression or self._generate_default_eval(field)
                instructions += f"""### Calculated Field {i}: {field.cim_field}

1. Click **New Calculated Field**
2. Configure:
   - **Name**: `{sourcetype}_{field.cim_field}_calc`
   - **Apply to**: `sourcetype` = `{sourcetype}`
   - **Eval Expression**: 
     ```
     {eval_expr}
     ```
3. Click **Save**

"""
        else:
            instructions += "_No Calculated Fields needed._\n\n"
        
        # Add validation section
        all_cim_fields = [f.cim_field for f in extracted_fields + calculated_fields]
        cim_fields_str = ', '.join(all_cim_fields[:10]) if all_cim_fields else 'action, src, dest'
        
        instructions += f"""---

## Step 4: Validation

### Test Field Mappings
```spl
sourcetype={sourcetype}
| head 10
| table _time, {cim_fields_str}
```

### Test CIM Compliance
```spl
| datamodel {data_model} {dataset} search
| search sourcetype={sourcetype}
| head 10
```

---

## Summary

| Category | Count |
|----------|-------|
| Field Aliases (extracted) | {len(extracted_fields)} |
| Calculated Fields (calculated) | {len(calculated_fields)} |
| Total Mappings | {len(extracted_fields) + len(calculated_fields)} |
"""
        
        return instructions
    
    def _generate_props_conf(self, calculated_fields: List[FieldMapping],
                            extracted_fields: List[FieldMapping],
                            sourcetype: str, data_model: str, dataset: str) -> str:
        """Generate props.conf configuration."""
        
        config = f"""# props.conf for {sourcetype}
# Data Model: {data_model} > {dataset}
# Generated by CIM Mapping Tool

[{sourcetype}]

# ============================================
# FIELD ALIASES (flag: extracted)
# ============================================
"""
        if extracted_fields:
            for field in extracted_fields:
                config += f"FIELDALIAS-{field.cim_field} = {field.raw_field} AS {field.cim_field}\n"
        else:
            config += "# No field aliases needed\n"
        
        config += """
# ============================================
# CALCULATED FIELDS (flag: calculated)
# ============================================
"""
        if calculated_fields:
            for field in calculated_fields:
                eval_expr = field.eval_expression or self._generate_default_eval(field)
                config += f"EVAL-{field.cim_field} = {eval_expr}\n"
        else:
            config += "# No calculated fields needed\n"
        
        return config
    
    def _generate_transforms_conf(self, sourcetype: str) -> str:
        """Generate transforms.conf if needed."""
        return f"# transforms.conf for {sourcetype}\n# No lookup transforms required for basic CIM mapping"
    
    def _generate_eventtypes_conf(self, sourcetype: str, data_model: str) -> str:
        """Generate eventtypes.conf configuration."""
        dm_safe = data_model.lower().replace(' ', '_') if data_model else 'unknown'
        return f"""# eventtypes.conf for {sourcetype}

[{sourcetype}_{dm_safe}]
search = sourcetype={sourcetype}
"""
    
    def _generate_tags_conf(self, sourcetype: str, data_model: str, tags: List[str]) -> str:
        """Generate tags.conf configuration."""
        dm_safe = data_model.lower().replace(' ', '_') if data_model else 'unknown'
        config = f"""# tags.conf for {sourcetype}

[eventtype={sourcetype}_{dm_safe}]
"""
        if tags:
            for tag in tags:
                config += f"{tag} = enabled\n"
        else:
            config += "# Add appropriate CIM tags\n"
        
        return config
    
    def _generate_validation_spl(self, sourcetype: str, data_model: str,
                                dataset: str, calculated_fields: List[FieldMapping],
                                extracted_fields: List[FieldMapping]) -> str:
        """Generate validation SPL queries."""
        
        all_fields = calculated_fields + extracted_fields
        cim_fields = [f.cim_field for f in all_fields[:15]]
        cim_fields_str = ', '.join(cim_fields) if cim_fields else 'action, src, dest'
        
        calc_fields_str = ', '.join([f.cim_field for f in calculated_fields[:10]]) or 'action'
        ext_fields_str = ', '.join([f.cim_field for f in extracted_fields[:10]]) or 'src_ip'
        
        return f"""# Validation SPL Queries for {sourcetype}

## 1. Test Raw Data
```spl
sourcetype={sourcetype}
| head 10
```

## 2. Test Field Aliases (Extracted Fields)
```spl
sourcetype={sourcetype}
| head 10
| table _time, {ext_fields_str}
```

## 3. Test Calculated Fields
```spl
sourcetype={sourcetype}
| head 10
| table _time, {calc_fields_str}
```

## 4. Verify All CIM Fields
```spl
sourcetype={sourcetype}
| head 10
| table _time, {cim_fields_str}
```

## 5. Test CIM Data Model Compliance
```spl
| datamodel {data_model} {dataset} search
| search sourcetype={sourcetype}
| head 10
| table _time, {cim_fields_str}
```

## 6. Verify Tags
```spl
sourcetype={sourcetype}
| head 1
| table tag
```

## Summary
- **Extracted Fields (Field Alias)**: {len(extracted_fields)}
- **Calculated Fields (EVAL)**: {len(calculated_fields)}
- **Total CIM Mappings**: {len(all_fields)}
"""
