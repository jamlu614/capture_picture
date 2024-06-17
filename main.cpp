#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/videodev2.h>
#include <libv4l2.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string>
#include <vector>
#include <iostream>
#include <mosquitto.h>
#include <chrono>
#include <atomic>
#include <signal.h>

#define CLEAR(x) memset(&(x), 0, sizeof(x))

struct mosquitto *local_mosq;
std::atomic<int64_t> interval_time(1000); //
int64_t last_timestamp = 0;
std::atomic<bool> exitFlag(false);

static void Handler(int sig)
{
    exitFlag.store(true, std::memory_order_relaxed);
    fprintf(stderr, "\nCaught Exiting...\n");
}

int64_t getTimestamp()
{
    // 获取当前系统时间点
    auto now = std::chrono::system_clock::now();

    // 转换为毫秒时间戳（自 1970-01-01 UTC）
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    return millis;
}

void connect_callback(struct mosquitto *mosq, void *obj, int result)
{
    mosquitto_subscribe(local_mosq, NULL, "capture-pic/interval_time", 1);
}

void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
    if (strcmp(msg->topic, "capture-pic/interval_time") == 0 && !exitFlag.load())
    {
        interval_time.store(atoi((char *)msg->payload) * 1000);
    }
}

void publishMessage(mosquitto *mosq, const char *message, const char *topic)
{
    int qos = 1;         // 服务质量等级（0, 1, 或 2）
    bool retain = false; // 是否保留消息
    // 发布启动失败消息
    int ret = mosquitto_publish(mosq, nullptr, topic, strlen(message), message, qos, retain);
    if (ret != MOSQ_ERR_SUCCESS)
    {
        std::cerr << "Error: Failed to publish message." << std::endl;
    }
    else
    {
        // std::cout << "publish topic:" << topic << std::endl;
    }
}

int init_local_mqtt()
{
    local_mosq = mosquitto_new("capture_picture", true, nullptr);
    mosquitto_connect_callback_set(local_mosq, connect_callback);
    mosquitto_message_callback_set(local_mosq, message_callback);
    if (mosquitto_connect(local_mosq, "localhost", 1883, 60) != MOSQ_ERR_SUCCESS)
    {
        std::cerr << "Online Mqtt failed to connect!" << std::endl;
        return -1;
    }
    std::cout << "mqtt init" << std::endl;
    mosquitto_loop_start(local_mosq);
    return 0;
}

// Base64编码函数（使用OpenSSL）
std::string base64Encode(const std::vector<unsigned char> &input)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.data(), input.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return result;
}

int main()
{

    signal(SIGQUIT, Handler);
    signal(SIGABRT, Handler);
    signal(SIGINT, Handler);
    init_local_mqtt();

    struct v4l2_format fmt;
    struct v4l2_buffer buf;
    struct v4l2_requestbuffers req;
    enum v4l2_buf_type type;
    fd_set fds;
    struct timeval tv;
    int r, fd = -1;
    unsigned int i, n_buffers;
    const char *dev_name = "/dev/video0";

    // 1. 打开摄像头设备
    fd = v4l2_open(dev_name, O_RDWR | O_NONBLOCK, 0);
    if (fd < 0)
    {
        perror("Cannot open device");
        exit(EXIT_FAILURE);
    }

    // 2. 设置视频格式（例如MJPG格式直接输出JPEG数据）
    CLEAR(fmt);
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = 640;
    fmt.fmt.pix.height = 480;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_MJPEG; // 直接获取JPEG数据
    fmt.fmt.pix.field = V4L2_FIELD_NONE;

    if (v4l2_ioctl(fd, VIDIOC_S_FMT, &fmt) < 0)
    {
        perror("Cannot set format");
        exit(EXIT_FAILURE);
    }

    struct v4l2_streamparm parm = {0};
    parm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

    if (ioctl(fd, VIDIOC_G_PARM, &parm) < 0)
    {
        perror("VIDIOC_G_PARM failed");
        close(fd);
        return EXIT_FAILURE;
    }

    // 设置帧率（例如 30 FPS）
    parm.parm.capture.timeperframe.numerator = 1;
    parm.parm.capture.timeperframe.denominator = 60;

    // 应用设置
    if (ioctl(fd, VIDIOC_S_PARM, &parm) < 0)
    {
        perror("VIDIOC_S_PARM failed");
        close(fd);
        return -1;
    }

    // 3. 请求缓冲区
    CLEAR(req);
    req.count = 1;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;

    if (v4l2_ioctl(fd, VIDIOC_REQBUFS, &req) < 0)
    {
        perror("Cannot request buffers");
        exit(EXIT_FAILURE);
    }

    // 4. 映射缓冲区
    void *buffer_start;
    CLEAR(buf);
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    buf.index = 0;

    if (v4l2_ioctl(fd, VIDIOC_QUERYBUF, &buf) < 0)
    {
        perror("Cannot query buffer");
        exit(EXIT_FAILURE);
    }

    buffer_start = v4l2_mmap(nullptr, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, buf.m.offset);
    if (buffer_start == MAP_FAILED)
    {
        perror("Cannot mmap buffer");
        exit(EXIT_FAILURE);
    }

    // 5. 入队缓冲区
    if (v4l2_ioctl(fd, VIDIOC_QBUF, &buf) < 0)
    {
        perror("Cannot queue buffer");
        exit(EXIT_FAILURE);
    }

    // 6. 开始视频流
    type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (v4l2_ioctl(fd, VIDIOC_STREAMON, &type) < 0)
    {
        perror("Cannot start stream");
        exit(EXIT_FAILURE);
    }

    // 7. 循环拍照并输出Base64
    while (!exitFlag.load())
    {
        // 等待数据就绪
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        r = select(fd + 1, &fds, NULL, NULL, &tv);

        if (r == -1)
        {
            perror("select error");
            break;
        }
        else if (r == 0)
        {
            fprintf(stderr, "select timeout\n");
            break;
        }

        // 取出帧
        CLEAR(buf);
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        if (v4l2_ioctl(fd, VIDIOC_DQBUF, &buf) < 0)
        {
            perror("Cannot dequeue buffer");
            break;
        }
        int64_t cur_timestamp = getTimestamp();
        if (cur_timestamp - last_timestamp >= interval_time.load())
        {
            std::vector<uint8_t> jpegData((uint8_t *)buffer_start, ((uint8_t *)buffer_start) + buf.bytesused);
            // Base64编码（直接使用JPEG数据）
            std::string base64_str = base64Encode(jpegData).data();
            // std::cout << "base64_data:" << base64_str << std::endl;
            publishMessage(local_mosq, base64_str.c_str(), "capture-pic/jpg");
            last_timestamp = cur_timestamp;
        }

        // 重新入队缓冲区
        if (v4l2_ioctl(fd, VIDIOC_QBUF, &buf) < 0)
        {
            perror("Cannot requeue buffer");
            break;
        }
    }

    // 8. 清理资源
    v4l2_munmap(buffer_start, buf.length);
    v4l2_close(fd);

    if (local_mosq)
    {
        mosquitto_loop_stop(local_mosq, true);
        mosquitto_disconnect(local_mosq);
        mosquitto_destroy(local_mosq);
    }
    mosquitto_lib_cleanup();
    return 0;
}