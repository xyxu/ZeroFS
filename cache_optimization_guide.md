

# ZeroFS 缓存优化指南

## 缓存架构概述

ZeroFS 使用多层缓存架构：
1. **内存缓存** (foyer-memory): 基于LRU的内存缓存，用于存储热点数据
2. **磁盘缓存** (slatedb): 本地磁盘缓存，存储最近访问的数据块
3. **预读缓存**: 顺序读取时的预读优化

## 性能优化建议

### 1. 内存缓存配置

**默认配置**: `memory_size_gb = 1.0`

**优化建议**:
- **轻度负载**: 1-2 GB
- **中等负载**: 2-4 GB  
- **重度负载**: 4-8 GB 或更多
- **生产环境**: 至少分配系统总内存的 10-20%

**配置示例**:
```toml
[cache]
memory_size_gb = 4.0  # 4GB内存缓存
```

### 2. 磁盘缓存配置

**默认配置**: `disk_size_gb = 10.0`

**优化建议**:
- **工作集大小**: 磁盘缓存应大于常用工作集
- **SSD vs HDD**: 使用SSD可显著提升性能
- **容量规划**: 
  - 开发环境: 10-50 GB
  - 生产环境: 100-500 GB 或更多
  - 大数据工作负载: 1 TB+

**配置示例**:
```toml
[cache]
disk_size_gb = 100.0  # 100GB磁盘缓存
```

### 3. 针对阿里云OSS的缓存优化

#### 3.1 减少网络往返
- 增大缓存以减少OSS请求
- 使用预读策略优化顺序访问

#### 3.2 缓存预热策略
```bash
# 预热常用目录
find /mnt/zerofs/frequently_used -type f -exec cat {} > /dev/null \;
```

#### 3.3 监控缓存命中率
```bash
# 查看缓存统计信息
zerofs stats --cache
```

### 4. 高级缓存调优

#### 4.1 LSM树缓存优化
```toml
[lsm]
l0_max_ssts = 32                   # 增加L0 SST文件数，减少压缩频率
max_unflushed_gb = 2.0             # 增加未刷新数据限制
max_concurrent_compactions = 16    # 增加并发压缩数
flush_interval_secs = 60           # 延长刷新间隔
```

#### 4.2 文件系统级优化
```toml
[filesystem]
max_size_gb = 1000.0               # 设置合理的文件系统大小限制
```

### 5. 监控和调优

#### 5.1 关键监控指标
- **缓存命中率**: 目标 > 80%
- **OSS请求延迟**: 监控P50, P90, P99
- **缓存使用率**: 避免频繁换出
- **网络吞吐量**: 确保带宽充足

#### 5.2 性能测试
```bash
# 运行基准测试
zerofs bench --duration 300 --threads 16

# 测试不同缓存配置
ZEROFS_CACHE_SIZE_GB=50 zerofs bench --duration 60
```

### 6. 故障排除

#### 6.1 缓存性能问题
**症状**: 高OSS延迟，低缓存命中率
**解决方案**:
- 增加缓存大小
- 检查磁盘IO性能
- 优化访问模式

#### 6.2 内存不足
**症状**: OOM killer终止进程
**解决方案**:
- 减少`memory_size_gb`
- 增加系统交换空间
- 使用内存限制工具

#### 6.3 磁盘空间不足
**症状**: 缓存无法增长，性能下降
**解决方案**:
- 增加`disk_size_gb`
- 清理旧缓存数据
- 使用专用缓存磁盘

### 7. 最佳实践总结

1. **分层配置**: 根据工作负载调整缓存层次
2. **监控驱动**: 基于实际使用情况调优
3. **容量规划**: 预留20-30%的缓存余量
4. **定期维护**: 监控和清理缓存目录
5. **测试验证**: 在生产前测试配置变更

### 8. 参考配置

#### 8.1 开发环境
```toml
[cache]
dir = "${HOME}/.cache/zerofs"
disk_size_gb = 20.0
memory_size_gb = 2.0
```

#### 8.2 生产环境（中等负载）
```toml
[cache]
dir = "/var/cache/zerofs"
disk_size_gb = 200.0
memory_size_gb = 8.0
```

#### 8.3 高性能环境
```toml
[cache]
dir = "/nvme/zerofs_cache"  # 使用NVMe SSD
disk_size_gb = 500.0
memory_size_gb = 16.0

[lsm]
max_concurrent_compactions = 32
l0_max_ssts = 64
```

