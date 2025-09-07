#!/usr/bin/env python3
"""
RAVN Data Generation Script
Generates synthetic training data for the AI model
"""

import numpy as np
import json
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any
import argparse
import os

# Syscall numbers
SYSCALLS = {
    'execve': 59,
    'open': 2,
    'openat': 257,
    'read': 0,
    'write': 1,
    'mmap': 9,
    'mprotect': 10,
    'close': 3,
    'unlink': 87,
    'rename': 82,
    'ptrace': 101,
    'setuid': 105,
    'chmod': 90,
    'chown': 92,
    'mount': 165,
    'umount': 166,
}

# Network event types
NETWORK_EVENTS = {
    'connect': 1,
    'bind': 2,
    'listen': 3,
    'accept': 4,
    'send': 5,
    'recv': 6,
}

# Security event types
SECURITY_EVENTS = {
    'ptrace': 1,
    'setuid': 2,
    'chmod': 3,
    'chown': 4,
    'mount': 5,
    'umount': 6,
}

# File event types
FILE_EVENTS = {
    'open': 1,
    'read': 2,
    'write': 3,
    'close': 4,
    'unlink': 5,
    'rename': 6,
}

class DataGenerator:
    def __init__(self, seed: int = 42):
        """Initialize the data generator"""
        random.seed(seed)
        np.random.seed(seed)
        
    def generate_normal_sequence(self, length: int = 10) -> List[Dict[str, Any]]:
        """Generate a normal system call sequence"""
        sequence = []
        base_time = datetime.now()
        
        # Common normal patterns
        normal_patterns = [
            ['open', 'read', 'close'],
            ['open', 'write', 'close'],
            ['execve'],
            ['mmap', 'mprotect'],
            ['open', 'read', 'write', 'close'],
        ]
        
        pattern = random.choice(normal_patterns)
        
        for i, syscall in enumerate(pattern[:length]):
            event = {
                'timestamp': int((base_time + timedelta(seconds=i)).timestamp() * 1e9),
                'pid': random.randint(1000, 9999),
                'tid': random.randint(1000, 9999),
                'event_type': SYSCALLS[syscall],
                'event_category': 1,  # syscall
                'comm': f'normal_process_{random.randint(1, 100)}',
                'data': json.dumps({
                    'syscall': syscall,
                    'ret': 0,
                    'filename': f'/tmp/file_{random.randint(1, 100)}.txt'
                })
            }
            sequence.append(event)
            
        return sequence
    
    def generate_suspicious_sequence(self, length: int = 15) -> List[Dict[str, Any]]:
        """Generate a suspicious system call sequence"""
        sequence = []
        base_time = datetime.now()
        
        # Suspicious patterns
        suspicious_patterns = [
            ['execve', 'open', 'read', 'read', 'read', 'close'],  # Multiple reads
            ['open', 'mmap', 'mprotect', 'execve'],  # Memory manipulation
            ['ptrace', 'setuid', 'execve'],  # Privilege escalation attempt
            ['open', 'read', 'write', 'unlink'],  # File manipulation
        ]
        
        pattern = random.choice(suspicious_patterns)
        
        for i, syscall in enumerate(pattern[:length]):
            event = {
                'timestamp': int((base_time + timedelta(milliseconds=i*100)).timestamp() * 1e9),
                'pid': random.randint(1000, 9999),
                'tid': random.randint(1000, 9999),
                'event_type': SYSCALLS[syscall],
                'event_category': 1,  # syscall
                'comm': f'suspicious_process_{random.randint(1, 100)}',
                'data': json.dumps({
                    'syscall': syscall,
                    'ret': 0,
                    'filename': f'/etc/passwd' if syscall in ['open', 'read'] else f'/tmp/file_{random.randint(1, 100)}.txt'
                })
            }
            sequence.append(event)
            
        return sequence
    
    def generate_attack_sequence(self, length: int = 20) -> List[Dict[str, Any]]:
        """Generate an attack system call sequence"""
        sequence = []
        base_time = datetime.now()
        
        # Attack patterns
        attack_patterns = [
            # Buffer overflow attempt
            ['execve', 'open', 'read', 'mmap', 'mprotect', 'execve'],
            # Privilege escalation
            ['ptrace', 'setuid', 'chmod', 'execve'],
            # File exfiltration
            ['open', 'read', 'read', 'read', 'write', 'close', 'unlink'],
            # Process injection
            ['ptrace', 'mmap', 'write', 'mprotect', 'execve'],
        ]
        
        pattern = random.choice(attack_patterns)
        
        for i, syscall in enumerate(pattern[:length]):
            event = {
                'timestamp': int((base_time + timedelta(milliseconds=i*50)).timestamp() * 1e9),
                'pid': random.randint(1000, 9999),
                'tid': random.randint(1000, 9999),
                'event_type': SYSCALLS[syscall],
                'event_category': 1,  # syscall
                'comm': f'attack_process_{random.randint(1, 100)}',
                'data': json.dumps({
                    'syscall': syscall,
                    'ret': 0,
                    'filename': f'/etc/shadow' if syscall in ['open', 'read'] else f'/tmp/exploit_{random.randint(1, 100)}.bin'
                })
            }
            sequence.append(event)
            
        return sequence
    
    def generate_network_events(self, count: int = 10) -> List[Dict[str, Any]]:
        """Generate network events"""
        events = []
        base_time = datetime.now()
        
        for i in range(count):
            event_type = random.choice(list(NETWORK_EVENTS.keys()))
            event = {
                'timestamp': int((base_time + timedelta(seconds=i)).timestamp() * 1e9),
                'pid': random.randint(1000, 9999),
                'tid': random.randint(1000, 9999),
                'event_type': NETWORK_EVENTS[event_type],
                'event_category': 2,  # network
                'comm': f'network_process_{random.randint(1, 100)}',
                'data': json.dumps({
                    'event': event_type,
                    'local_ip': f'192.168.1.{random.randint(1, 254)}',
                    'local_port': random.randint(1024, 65535),
                    'remote_ip': f'10.0.0.{random.randint(1, 254)}',
                    'remote_port': random.randint(1024, 65535)
                })
            }
            events.append(event)
            
        return events
    
    def generate_security_events(self, count: int = 5) -> List[Dict[str, Any]]:
        """Generate security events"""
        events = []
        base_time = datetime.now()
        
        for i in range(count):
            event_type = random.choice(list(SECURITY_EVENTS.keys()))
            event = {
                'timestamp': int((base_time + timedelta(seconds=i)).timestamp() * 1e9),
                'pid': random.randint(1000, 9999),
                'tid': random.randint(1000, 9999),
                'event_type': SECURITY_EVENTS[event_type],
                'event_category': 3,  # security
                'comm': f'security_process_{random.randint(1, 100)}',
                'data': json.dumps({
                    'event': event_type,
                    'target_pid': random.randint(1000, 9999),
                    'uid': random.randint(0, 1000),
                    'gid': random.randint(0, 1000),
                    'pathname': f'/etc/{event_type}_target'
                })
            }
            events.append(event)
            
        return events
    
    def generate_file_events(self, count: int = 8) -> List[Dict[str, Any]]:
        """Generate file events"""
        events = []
        base_time = datetime.now()
        
        for i in range(count):
            event_type = random.choice(list(FILE_EVENTS.keys()))
            event = {
                'timestamp': int((base_time + timedelta(seconds=i)).timestamp() * 1e9),
                'pid': random.randint(1000, 9999),
                'tid': random.randint(1000, 9999),
                'event_type': FILE_EVENTS[event_type],
                'event_category': 4,  # file
                'comm': f'file_process_{random.randint(1, 100)}',
                'data': json.dumps({
                    'event': event_type,
                    'fd': random.randint(3, 100),
                    'size': random.randint(1, 4096),
                    'filename': f'/tmp/file_{random.randint(1, 100)}.txt',
                    'target_filename': f'/tmp/target_{random.randint(1, 100)}.txt'
                })
            }
            events.append(event)
            
        return events
    
    def generate_training_dataset(self, num_normal: int = 1000, num_suspicious: int = 500, num_attack: int = 200) -> Dict[str, List[Dict[str, Any]]]:
        """Generate complete training dataset"""
        print(f"Generating {num_normal} normal sequences...")
        normal_sequences = []
        for _ in range(num_normal):
            sequence = self.generate_normal_sequence(random.randint(5, 15))
            normal_sequences.append({
                'sequence': sequence,
                'label': 0,  # Normal
                'threat_score': random.uniform(0.0, 0.3)
            })
        
        print(f"Generating {num_suspicious} suspicious sequences...")
        suspicious_sequences = []
        for _ in range(num_suspicious):
            sequence = self.generate_suspicious_sequence(random.randint(10, 20))
            suspicious_sequences.append({
                'sequence': sequence,
                'label': 1,  # Suspicious
                'threat_score': random.uniform(0.3, 0.7)
            })
        
        print(f"Generating {num_attack} attack sequences...")
        attack_sequences = []
        for _ in range(num_attack):
            sequence = self.generate_attack_sequence(random.randint(15, 25))
            attack_sequences.append({
                'sequence': sequence,
                'label': 2,  # Attack
                'threat_score': random.uniform(0.7, 1.0)
            })
        
        # Generate additional event types
        print("Generating network events...")
        network_events = self.generate_network_events(100)
        
        print("Generating security events...")
        security_events = self.generate_security_events(50)
        
        print("Generating file events...")
        file_events = self.generate_file_events(80)
        
        return {
            'normal_sequences': normal_sequences,
            'suspicious_sequences': suspicious_sequences,
            'attack_sequences': attack_sequences,
            'network_events': network_events,
            'security_events': security_events,
            'file_events': file_events,
        }

def main():
    parser = argparse.ArgumentParser(description='Generate synthetic training data for RAVN AI model')
    parser.add_argument('--output', '-o', default='training_data.json', help='Output file path')
    parser.add_argument('--normal', type=int, default=1000, help='Number of normal sequences')
    parser.add_argument('--suspicious', type=int, default=500, help='Number of suspicious sequences')
    parser.add_argument('--attack', type=int, default=200, help='Number of attack sequences')
    parser.add_argument('--seed', type=int, default=42, help='Random seed')
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    
    # Generate data
    generator = DataGenerator(seed=args.seed)
    dataset = generator.generate_training_dataset(
        num_normal=args.normal,
        num_suspicious=args.suspicious,
        num_attack=args.attack
    )
    
    # Save dataset
    print(f"Saving dataset to {args.output}...")
    with open(args.output, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print("Data generation completed!")
    print(f"Generated:")
    print(f"  - {len(dataset['normal_sequences'])} normal sequences")
    print(f"  - {len(dataset['suspicious_sequences'])} suspicious sequences")
    print(f"  - {len(dataset['attack_sequences'])} attack sequences")
    print(f"  - {len(dataset['network_events'])} network events")
    print(f"  - {len(dataset['security_events'])} security events")
    print(f"  - {len(dataset['file_events'])} file events")

if __name__ == '__main__':
    main()
