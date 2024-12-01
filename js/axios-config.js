// axios 기본 설정
axios.defaults.baseURL =
  "https://port-0-attend-backend-m0tl39wtc3a73922.sel4.cloudtype.app";

// axios 인터셉터 설정
axios.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // 토큰이 만료되었고, 재시도하지 않은 요청인 경우
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshToken = localStorage.getItem("refreshToken");
        if (!refreshToken) {
          throw new Error("리프레시 토큰이 없습니다.");
        }

        // 토큰 갱신 요청
        const response = await axios.post("/api/refresh-token", {
          refreshToken,
        });

        if (!response.data.success) {
          throw new Error(response.data.message);
        }

        // 새로운 토큰 저장
        localStorage.setItem("token", response.data.accessToken);
        localStorage.setItem("refreshToken", response.data.refreshToken);
        localStorage.setItem("userInfo", JSON.stringify(response.data.user));

        // 원래 요청 헤더 업데이트
        originalRequest.headers.Authorization = `Bearer ${response.data.accessToken}`;

        // 원래 요청 재시도
        return axios(originalRequest);
      } catch (error) {
        console.error("Token refresh failed:", error);
        localStorage.clear();
        window.location.href =
          "index.html?error=" +
          encodeURIComponent("세션이 만료되었습니다. 다시 로그인해주세요.");
        return Promise.reject(error);
      }
    }
    return Promise.reject(error);
  }
);
