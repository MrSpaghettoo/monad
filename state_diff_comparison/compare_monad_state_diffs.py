#!/usr/bin/env python3
"""
Script to compare state diffs between Monad's implementation and reference Ethereum client
using debug_traceTransaction RPC calls for block 21881388.
"""

import json
import requests
import sys
import os
import hashlib
from typing import Dict, List, Tuple, Any, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict
import time

from Crypto.Hash import keccak

@dataclass
class StateChange:
    """Represents a single state change"""
    address: str
    field: str  # 'balance', 'nonce', 'code', or storage key
    old_value: str
    new_value: str
    change_type: str  # 'account', 'storage', 'code'
    transaction_hash: str = ""

@dataclass
class TransactionInfo:
    """Information about a transaction"""
    hash: str
    index: int
    from_address: str
    to_address: str
    value: str
    gas_used: str

class MonadStateDiffComparator:
    """Comparator for state diffs between Monad and reference implementation"""
    
    def __init__(self, rpc_url: str):
        self.rpc_url = rpc_url
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})
    
    def make_rpc_call(self, method: str, params: List[Any]) -> Dict[str, Any]:
        """Make an RPC call to the Ethereum node"""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }
        
        try:
            response = self.session.post(self.rpc_url, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            if 'error' in result:
                print(f"RPC Error: {result['error']}")
                return {}
            
            return result.get('result', {})
        except Exception as e:
            print(f"RPC call failed: {e}")
            return {}
    
    def get_block_transactions(self, block_number: int) -> List[TransactionInfo]:
        """Get all transactions in a block"""
        print(f"Fetching transactions for block {block_number}...")
        
        block_data = self.make_rpc_call("eth_getBlockByNumber", [hex(block_number), True])
        if not block_data:
            return []
        
        transactions = []
        for i, tx in enumerate(block_data.get('transactions', [])):
            tx_info = TransactionInfo(
                hash=tx.get('hash', ''),
                index=i,
                from_address=tx.get('from', ''),
                to_address=tx.get('to', ''),
                value=tx.get('value', '0x0'),
                gas_used=tx.get('gas', '0x0')
            )
            transactions.append(tx_info)
        
        print(f"Found {len(transactions)} transactions in block {block_number}")
        return transactions
    
    def trace_transaction(self, tx_hash: str, trace_type: str = "prestateTracer") -> Dict[str, Any]:
        """Trace a single transaction using debug_traceTransaction"""
        print(f"Tracing transaction {tx_hash}...")
        
        if trace_type == "prestateTracer":
            params = [tx_hash, {"tracer": "prestateTracer", "tracerConfig": {"diffMode": True}}]
        elif trace_type == "callTracer":
            params = [tx_hash, {"tracer": "callTracer"}]
        else:
            params = [tx_hash, {"tracer": trace_type}]
        
        result = self.make_rpc_call("debug_traceTransaction", params)
        
        if not result:
            print(f"Failed to trace transaction {tx_hash}")
            return {}
        
        return result
    
    def parse_prestate_trace(self, trace_result: Dict[str, Any], tx_hash: str) -> List[StateChange]:
        """Parse prestateTracer result to extract state changes"""
        changes = []
        
        if not trace_result:
            return changes
        
        pre_state = trace_result.get('pre', {})
        post_state = trace_result.get('post', {})
        
        all_addresses = set(pre_state.keys()) | set(post_state.keys())
        
        for address in all_addresses:
            pre_account = pre_state.get(address, {})
            post_account = post_state.get(address, {})
            
            if not pre_account and post_account:
                for field in ['balance', 'nonce', 'code']:
                    if field in post_account:
                        post_val = post_account[field]
                        if field == 'balance' and post_val != '0x0':
                            changes.append(StateChange(
                                address=address,
                                field=field,
                                old_value='0x0',
                                new_value=post_val,
                                change_type='account',
                                transaction_hash=tx_hash
                            ))
                        elif field == 'nonce' and post_val != '0':
                            changes.append(StateChange(
                                address=address,
                                field=field,
                                old_value='0',
                                new_value=str(post_val),
                                change_type='account',
                                transaction_hash=tx_hash
                            ))
                        elif field == 'code' and post_val != '0x':
                            changes.append(StateChange(
                                address=address,
                                field=field,
                                old_value='0x',
                                new_value=post_val,
                                change_type='code',
                                transaction_hash=tx_hash
                            ))
            
            elif pre_account and not post_account:
                for field in ['balance', 'nonce', 'code']:
                    if field in pre_account:
                        pre_val = pre_account[field]
                        if field == 'balance' and pre_val != '0x0':
                            changes.append(StateChange(
                                address=address,
                                field=field,
                                old_value=pre_val,
                                new_value='0x0',
                                change_type='account',
                                transaction_hash=tx_hash
                            ))
                        elif field == 'nonce' and pre_val != '0':
                            changes.append(StateChange(
                                address=address,
                                field=field,
                                old_value=str(pre_val),
                                new_value='0',
                                change_type='account',
                                transaction_hash=tx_hash
                            ))
                        elif field == 'code' and pre_val != '0x':
                            changes.append(StateChange(
                                address=address,
                                field=field,
                                old_value=pre_val,
                                new_value='0x',
                                change_type='code',
                                transaction_hash=tx_hash
                            ))
            
            elif pre_account and post_account == {}:
                pass
            
            elif pre_account and post_account and post_account != {}:
                for field in ['balance', 'nonce', 'code']:
                    if field in pre_account and field in post_account:
                        pre_val = pre_account[field]
                        post_val = post_account[field]
                        
                        if field == 'balance' or field == 'code':
                            pre_val = pre_val if pre_val.startswith('0x') else '0x' + pre_val
                            post_val = post_val if post_val.startswith('0x') else '0x' + post_val
                        elif field == 'nonce':
                            pre_val = str(pre_val) if pre_val != '0x0' else '0'
                            post_val = str(post_val) if post_val != '0x0' else '0'
                        
                        if pre_val != post_val:
                            change_type = 'code' if field == 'code' else 'account'
                            changes.append(StateChange(
                                address=address,
                                field=field,
                                old_value=pre_val,
                                new_value=post_val,
                                change_type=change_type,
                                transaction_hash=tx_hash
                            ))
                    elif field not in pre_account and field in post_account:
                        post_val = post_account[field]
                        
                        if field == 'balance':
                            pre_val = '0x0'
                        elif field == 'nonce':
                            pre_val = '0'
                        elif field == 'code':
                            pre_val = '0x'
                        
                        if field == 'balance' or field == 'code':
                            post_val = post_val if post_val.startswith('0x') else '0x' + post_val
                        elif field == 'nonce':
                            post_val = str(post_val) if post_val != '0x0' else '0'
                        
                        if pre_val != post_val:
                            change_type = 'code' if field == 'code' else 'account'
                            changes.append(StateChange(
                                address=address,
                                field=field,
                                old_value=pre_val,
                                new_value=post_val,
                                change_type=change_type,
                                transaction_hash=tx_hash
                            ))
            
            # Compare storage
            pre_storage = pre_account.get('storage', {})
            post_storage = post_account.get('storage', {})
            
            all_storage_keys = set(pre_storage.keys()) | set(post_storage.keys())
            
            for storage_key in all_storage_keys:
                pre_val = pre_storage.get(storage_key, '0x0')
                post_val = post_storage.get(storage_key, '0x0')
                
                pre_val = pre_val if pre_val.startswith('0x') else '0x' + pre_val
                post_val = post_val if post_val.startswith('0x') else '0x' + post_val
                
                if pre_val != post_val:
                    changes.append(StateChange(
                        address=address,
                        field=storage_key,
                        old_value=pre_val,
                        new_value=post_val,
                        change_type='storage',
                        transaction_hash=tx_hash
                    ))
        
        return changes
    
    def is_meaningful_change(self, old_value: str, new_value: str) -> bool:
        """Check if a change is meaningful (not just 0->0 or same value)"""
        old_norm = self.normalize_hex_value(old_value)
        new_norm = self.normalize_hex_value(new_value)
        return old_norm != new_norm

    def parse_monad_log(self, log_file: str) -> List[StateChange]:
        """Parse Monad's failblock.log to extract state changes"""
        changes = []
        
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"Log file {log_file} not found")
            return changes
        
        current_transaction = None
        current_address = None
        in_account_changes = False
        in_storage_changes = False
        
        for line in lines:
            line = line.strip()

            if "Transaction" in line and "state changes before merge" in line:
                # Extract transaction number from line like "LOG_DEBUG	Transaction 0 state changes before merge:"
                import re
                match = re.search(r'Transaction (\d+)', line)
                if match:
                    current_transaction = int(match.group(1))
                continue

            if "Address: 0x" in line:
                # Extract address from line like "LOG_DEBUG	  Address: 0x1db6ab3ba5f5c152b9d8733630ec7b0f42bb9028"
                import re
                match = re.search(r'Address: (0x[0-9a-fA-F]+)', line)
                if match:
                    current_address = match.group(1)
                    in_account_changes = False
                    in_storage_changes = False
                continue

            if "Account changes:" in line:
                in_account_changes = True
                in_storage_changes = False
                continue

            if "Storage changes:" in line:
                in_storage_changes = True
                in_account_changes = False
                continue

            if in_account_changes and current_address and current_transaction is not None:
                if "nonce:" in line:
                    # Format: "LOG_DEBUG	      nonce: 1 -> 2"
                    import re
                    match = re.search(r'nonce:\s*(\d+)\s*->\s*(\d+)', line)
                    if match:
                        old_val = match.group(1)
                        new_val = match.group(2)
                        if self.is_meaningful_change(old_val, new_val):
                            changes.append(StateChange(
                                address=current_address,
                                field='nonce',
                                old_value=old_val,
                                new_value=new_val,
                                change_type='account',
                                transaction_hash=f"tx_{current_transaction}"
                            ))
                
                elif "balance:" in line:
                    # Format: "LOG_DEBUG	      balance: 0x3649143c2b0000 -> 0x201ff6133e3200"
                    import re
                    match = re.search(r'balance:\s*(0x[0-9a-fA-F]+)\s*->\s*(0x[0-9a-fA-F]+)', line)
                    if match:
                        old_val = match.group(1)
                        new_val = match.group(2)
                        if self.is_meaningful_change(old_val, new_val):
                            changes.append(StateChange(
                                address=current_address,
                                field='balance',
                                old_value=old_val,
                                new_value=new_val,
                                change_type='account',
                                transaction_hash=f"tx_{current_transaction}"
                            ))
                
                elif "code_hash:" in line:
                    # Format: "LOG_DEBUG	      code_hash: 0x... -> 0x..."
                    import re
                    match = re.search(r'code_hash:\s*(0x[0-9a-fA-F]+)\s*->\s*(0x[0-9a-fA-F]+)', line)
                    if match:
                        old_val = match.group(1)
                        new_val = match.group(2)
                        if self.is_meaningful_change(old_val, new_val):
                            changes.append(StateChange(
                                address=current_address,
                                field='code_hash',  # Use code_hash for Monad
                                old_value=old_val,
                                new_value=new_val,
                                change_type='code',
                                transaction_hash=f"tx_{current_transaction}"
                            ))

            elif "Account created:" in line and current_address and current_transaction is not None:
                # Format: "Account created: nonce=0, balance=0x69017aeb4dc800, code_hash=0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                import re
                nonce_match = re.search(r'nonce=(\d+)', line)
                balance_match = re.search(r'balance=(0x[0-9a-fA-F]+)', line)
                code_hash_match = re.search(r'code_hash=(0x[0-9a-fA-F]+)', line)
                
                if nonce_match:
                    new_nonce = nonce_match.group(1)
                    if self.is_meaningful_change('0', new_nonce):
                        changes.append(StateChange(
                            address=current_address,
                            field='nonce',
                            old_value='0',
                            new_value=new_nonce,
                            change_type='account',
                            transaction_hash=f"tx_{current_transaction}"
                        ))
                
                if balance_match:
                    new_balance = balance_match.group(1)
                    if self.is_meaningful_change('0x0', new_balance):
                        changes.append(StateChange(
                            address=current_address,
                            field='balance',
                            old_value='0x0',
                            new_value=new_balance,
                            change_type='account',
                            transaction_hash=f"tx_{current_transaction}"
                        ))
                
                if code_hash_match:
                    new_code_hash = code_hash_match.group(1)
                    default_code_hash = self.hash_code_content("0x")
                    if self.is_meaningful_change(default_code_hash, new_code_hash):
                        changes.append(StateChange(
                            address=current_address,
                            field='code_hash',  # Use code_hash for Monad
                            old_value=default_code_hash,
                            new_value=new_code_hash,
                            change_type='code',
                            transaction_hash=f"tx_{current_transaction}"
                        ))

            elif "Account deleted" in line and current_address and current_transaction is not None:
                # Format: "Account deleted (was: nonce=2244798, balance=0xab9088be7d3c7d79f3)"
                import re
                nonce_match = re.search(r'nonce=(\d+)', line)
                balance_match = re.search(r'balance=(0x[0-9a-fA-F]+)', line)
                
                if nonce_match:
                    old_nonce = nonce_match.group(1)
                    if self.is_meaningful_change(old_nonce, '0'):
                        changes.append(StateChange(
                            address=current_address,
                            field='nonce',
                            old_value=old_nonce,
                            new_value='0',
                            change_type='account',
                            transaction_hash=f"tx_{current_transaction}"
                        ))
                
                if balance_match:
                    old_balance = balance_match.group(1)
                    if self.is_meaningful_change(old_balance, '0x0'):
                        changes.append(StateChange(
                            address=current_address,
                            field='balance',
                            old_value=old_balance,
                            new_value='0x0',
                            change_type='account',
                            transaction_hash=f"tx_{current_transaction}"
                        ))

            elif in_storage_changes and current_address and current_transaction is not None:
                if ": " in line and " -> " in line:
                    # Format: "LOG_DEBUG	      0x2eff62b6c6fb62dfea87cd0495e84370130134389af8e16f2d6407aa8d154aca: 0x0000000000000000000000000000000000000000000000000000000001bfbe5b -> 0x0000000000000000000000000000000000000000000000000000000000000000"
                    import re
                    match = re.search(r'(0x[0-9a-fA-F]+):\s*(0x[0-9a-fA-F]+)\s*->\s*(0x[0-9a-fA-F]+)', line)
                    if match:
                        storage_key = match.group(1)
                        old_val = match.group(2)
                        new_val = match.group(3)
                        if self.is_meaningful_change(old_val, new_val):
                            changes.append(StateChange(
                                address=current_address,
                                field=storage_key,
                                old_value=old_val,
                                new_value=new_val,
                                change_type='storage',
                                transaction_hash=f"tx_{current_transaction}"
                            ))
        
        return changes
    
    def get_monad_state_diffs(self, block_number: int) -> List[StateChange]:
        """Get state diffs from Monad's failblock.log"""
        log_file = "../failblock.log"  # Path relative to subdirectory
        print(f"Parsing Monad state diffs from {log_file}...")
        
        changes = self.parse_monad_log(log_file)
        print(f"Found {len(changes)} state changes in Monad log")
        
        return changes
    
    def normalize_hex_value(self, value: str) -> str:
        """Normalize hex values for comparison"""
        if not value.startswith('0x'):
            return value
        
        # Remove 0x prefix and convert to int, then back to hex
        try:
            if value == '0x0' or value == '0x':
                return '0x0'
            
            int_val = int(value, 16)
            if int_val == 0:
                return '0x0'
            else:
                return hex(int_val)
        except ValueError:
            return value
    
    def hash_code_content(self, code_content: str) -> str:
        """Hash code content to get code hash for comparison using Keccak-256"""
        if not code_content or code_content == '0x' or code_content == '0x0':
            code_bytes = b''
        else:
            if code_content.startswith('0x'):
                hex_string = code_content[2:]
            else:
                hex_string = code_content

            if len(hex_string) % 2 != 0:
                hex_string = '0' + hex_string
            
            try:
                code_bytes = bytes.fromhex(hex_string)
            except ValueError as e:
                print(f"Error decoding hex: {e}")
                return self.hash_code_content("0x")

        k = keccak.new(digest_bits=256)
        k.update(code_bytes)
        return '0x' + k.hexdigest()

    def normalize_field_name(self, change: StateChange, is_reference: bool) -> str:
        """Normalize field names for comparison between reference and Monad"""
        if change.change_type == 'code':
            if is_reference:
                return 'code_hash'  # Convert reference 'code' to 'code_hash' for comparison
            else:
                return 'code_hash'  # Monad already uses 'code_hash'
        return change.field

    def compare_state_diffs(self, reference_diffs: List[StateChange], monad_diffs: List[StateChange], tx_mapping: Dict[int, str] = None) -> Dict[str, Any]:
        """Compare state diffs between reference and Monad implementations"""
        print("Comparing state diffs...")

        ref_by_tx = defaultdict(list)
        monad_by_tx = defaultdict(list)
        
        for change in reference_diffs:
            ref_by_tx[change.transaction_hash].append(change)
        
        for change in monad_diffs:
            monad_by_tx[change.transaction_hash].append(change)

        if tx_mapping:
            normalized_monad_diffs = []
            for change in monad_diffs:
                if change.transaction_hash.startswith("tx_"):
                    try:
                        tx_index = int(change.transaction_hash.split("_")[1])
                        if tx_index in tx_mapping:
                            normalized_change = StateChange(
                                address=change.address,
                                field=change.field,
                                old_value=change.old_value,
                                new_value=change.new_value,
                                change_type=change.change_type,
                                transaction_hash=tx_mapping[tx_index]
                            )
                            normalized_monad_diffs.append(normalized_change)
                        else:
                            normalized_monad_diffs.append(change)
                    except (ValueError, IndexError):
                        normalized_monad_diffs.append(change)
                else:
                    normalized_monad_diffs.append(change)

            monad_by_tx = defaultdict(list)
            for change in normalized_monad_diffs:
                monad_by_tx[change.transaction_hash].append(change)
        
        differences = {
            'missing_in_monad': [],
            'extra_in_monad': [],
            'different_values': [],
            'summary': {
                'total_reference_changes': len(reference_diffs),
                'total_monad_changes': len(monad_diffs),
                'transactions_with_differences': 0,
                'transactions_processed': len(ref_by_tx)
            }
        }
        
        all_tx_hashes = set(ref_by_tx.keys()) | set(monad_by_tx.keys())
        
        for tx_hash in all_tx_hashes:
            ref_changes = ref_by_tx.get(tx_hash, [])
            monad_changes = monad_by_tx.get(tx_hash, [])

            ref_lookup = {}
            for change in ref_changes:
                normalized_field = self.normalize_field_name(change, is_reference=True)

                if change.change_type == 'code' and change.field == 'code':
                    hashed_old = self.hash_code_content(change.old_value)
                    hashed_new = self.hash_code_content(change.new_value)
                    hashed_change = StateChange(
                        address=change.address,
                        field='code_hash',
                        old_value=hashed_old,
                        new_value=hashed_new,
                        change_type=change.change_type,
                        transaction_hash=change.transaction_hash
                    )
                    key = (change.address, normalized_field, change.change_type)
                    ref_lookup[key] = hashed_change
                else:
                    key = (change.address, normalized_field, change.change_type)
                    ref_lookup[key] = change
            
            monad_lookup = {}
            for change in monad_changes:
                normalized_field = self.normalize_field_name(change, is_reference=False)
                key = (change.address, normalized_field, change.change_type)
                monad_lookup[key] = change
            
            tx_has_differences = False
            
            for key, ref_change in ref_lookup.items():
                if key not in monad_lookup:
                    differences['missing_in_monad'].append(ref_change)
                    tx_has_differences = True
                else:
                    monad_change = monad_lookup[key]

                    ref_old_norm = self.normalize_hex_value(ref_change.old_value)
                    ref_new_norm = self.normalize_hex_value(ref_change.new_value)
                    monad_old_norm = self.normalize_hex_value(monad_change.old_value)
                    monad_new_norm = self.normalize_hex_value(monad_change.new_value)
                    
                    if (ref_old_norm != monad_old_norm or ref_new_norm != monad_new_norm):
                        differences['different_values'].append({
                            'reference': ref_change,
                            'monad': monad_change,
                            'normalized_comparison': {
                                'ref_old': ref_old_norm,
                                'ref_new': ref_new_norm,
                                'monad_old': monad_old_norm,
                                'monad_new': monad_new_norm
                            }
                        })
                        tx_has_differences = True

            for key, monad_change in monad_lookup.items():
                if key not in ref_lookup:
                    differences['extra_in_monad'].append(monad_change)
                    tx_has_differences = True
            
            if tx_has_differences:
                differences['summary']['transactions_with_differences'] += 1
        
        return differences
    
    def analyze_block(self, block_number: int, tracer_type: str = "prestateTracer") -> Dict[str, Any]:
        """Analyze a complete block for state diff differences"""
        print(f"Analyzing block {block_number} with tracer {tracer_type}...")

        transactions = self.get_block_transactions(block_number)
        if not transactions:
            print(f"No transactions found in block {block_number}")
            return {}

        all_reference_diffs = []
        successful_traces = 0
        
        for tx in transactions:
            print(f"Processing transaction {tx.index}: {tx.hash}")

            trace_result = self.trace_transaction(tx.hash, tracer_type)
            if trace_result:
                changes = self.parse_prestate_trace(trace_result, tx.hash)
                if changes:
                    all_reference_diffs.extend(changes)
                    successful_traces += 1
                    print(f"  Found {len(changes)} state changes")
                else:
                    print(f"  No state changes found in trace")
            else:
                print(f"  Failed to trace transaction")
        
        print(f"Successfully traced {successful_traces}/{len(transactions)} transactions")
        print(f"Total reference state changes: {len(all_reference_diffs)}")
        monad_diffs = self.get_monad_state_diffs(block_number)

        tx_mapping = {}
        for i, tx in enumerate(transactions):
            tx_mapping[i] = tx.hash

        comparison_result = self.compare_state_diffs(all_reference_diffs, monad_diffs, tx_mapping)
        
        return {
            'block_number': block_number,
            'transactions_processed': len(transactions),
            'successful_traces': successful_traces,
            'reference_diffs': all_reference_diffs,
            'monad_diffs': monad_diffs,
            'comparison': comparison_result
        }
    
    def save_results(self, results: Dict[str, Any], filename: str = None):
        """Save analysis results to file"""
        if filename is None:
            filename = f"monad_state_diff_analysis_{results['block_number']}.json"

        def convert_to_dict(obj):
            if hasattr(obj, '__dict__'):
                return {k: convert_to_dict(v) for k, v in obj.__dict__.items()}
            elif isinstance(obj, list):
                return [convert_to_dict(item) for item in obj]
            elif isinstance(obj, dict):
                return {k: convert_to_dict(v) for k, v in obj.items()}
            else:
                return obj
        
        serializable_results = convert_to_dict(results)
        
        with open(filename, 'w') as f:
            json.dump(serializable_results, f, indent=2)
        
        print(f"Results saved to {filename}")

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: script.py RPC_URL [BLOCK_NUMBER] [TRACER_TYPE]")
        print("RPC_URL: Required Ethereum node RPC endpoint")
        print("BLOCK_NUMBER: Optional block number (default: 21881388)")
        print("TRACER_TYPE: Optional tracer type - 'prestateTracer' or 'callTracer' (default: prestateTracer)")
        sys.exit(1)

    rpc_url = sys.argv[1]
    block_number = 21881388
    tracer_type = "prestateTracer"

    if len(sys.argv) > 2:
        try:
            block_number = int(sys.argv[2])
        except ValueError:
            print(f"Invalid block number: {sys.argv[2]}")
            sys.exit(1)
    
    if len(sys.argv) > 3:
        tracer_type = sys.argv[3]
        if tracer_type not in ["prestateTracer", "callTracer"]:
            print(f"Invalid tracer type: {tracer_type}. Use 'prestateTracer' or 'callTracer'")
            sys.exit(1)
    
    print(f"Starting Monad state diff comparison for block {block_number}")
    print(f"Using tracer: {tracer_type}")
    print(f"RPC URL: {rpc_url}")

    comparator = MonadStateDiffComparator(rpc_url)

    results = comparator.analyze_block(block_number, tracer_type)
    
    if not results:
        print("Analysis failed")
        return

    print("\n" + "="*60)
    print("ANALYSIS SUMMARY")
    print("="*60)
    print(f"Block: {results['block_number']}")
    print(f"Transactions processed: {results['transactions_processed']}")
    print(f"Successful traces: {results['successful_traces']}")
    print(f"Reference state changes: {len(results['reference_diffs'])}")
    print(f"Monad state changes: {len(results['monad_diffs'])}")
    
    comparison = results['comparison']
    print(f"Transactions with differences: {comparison['summary']['transactions_with_differences']}")
    print(f"Missing in Monad: {len(comparison['missing_in_monad'])}")
    print(f"Extra in Monad: {len(comparison['extra_in_monad'])}")
    print(f"Different values: {len(comparison['different_values'])}")

    comparator.save_results(results)

    if comparison['missing_in_monad']:
        print("\nExample missing changes in Monad:")
        for change in comparison['missing_in_monad'][:5]:
            print(f"  {change.address}: {change.field} {change.old_value} -> {change.new_value}")
    
    if comparison['extra_in_monad']:
        print("\nExample extra changes in Monad:")
        for change in comparison['extra_in_monad'][:5]:
            print(f"  {change.address}: {change.field} {change.old_value} -> {change.new_value}")

if __name__ == "__main__":
    main()
